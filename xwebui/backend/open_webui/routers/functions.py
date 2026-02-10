import os
import re
import ast

import logging
import aiohttp
from pathlib import Path
from typing import Optional, List

from open_webui.models.functions import (
    FunctionForm,
    FunctionModel,
    FunctionResponse,
    FunctionWithValvesModel,
    Functions,
)
from open_webui.utils.plugin import (
    load_function_module_by_id,
    replace_imports,
    get_function_module_from_cache,
)
from open_webui.config import CACHE_DIR
from open_webui.constants import ERROR_MESSAGES
from fastapi import APIRouter, Depends, HTTPException, Request, status
from open_webui.utils.auth import get_admin_user, get_verified_user
from open_webui.env import SRC_LOG_LEVELS
from pydantic import BaseModel, HttpUrl, Field


log = logging.getLogger(__name__)
log.setLevel(SRC_LOG_LEVELS["MAIN"])


############################
# Pipe Argument Models
############################


class PipeArgument(BaseModel):
    name: str
    type: str = "string"  # string, number, boolean, select
    description: str = ""
    default: Optional[str] = None
    options: Optional[List[str]] = None  # For select type
    required: bool = False
    prefix: str = "—"  # The prefix used in prompts (e.g., "—" for "—strength")


class PipeArgumentsSpec(BaseModel):
    arguments: List[PipeArgument] = []
    description: str = ""


def extract_pipe_arguments_from_code(code: str) -> PipeArgumentsSpec:
    """
    Extract pipe arguments from Python code by analyzing regex patterns
    that look for flags in the prompt text.

    Detection strategies (in order):
    1. Explicit PIPE_ARGUMENTS list constant in module scope
    2. Dict-based param_patterns like {"duration": (r"—duration\\s+(\\d+)", int), ...}
    3. Individual re.search / re.sub calls with em-dash (—) or double-dash (--) flags
    """
    arguments = []
    seen_args = set()

    # ── Strategy 1: Explicit PIPE_ARGUMENTS constant ───────────────────
    pipe_args_match = re.search(
        r'PIPE_ARGUMENTS\s*=\s*(\[[\s\S]*?\])\s*(?:\n\n|\nclass|\ndef|\Z)',
        code
    )
    if pipe_args_match:
        try:
            args_str = pipe_args_match.group(1)
            explicit_args = ast.literal_eval(args_str)
            for arg in explicit_args:
                if isinstance(arg, dict) and 'name' in arg:
                    arg_name = arg['name'].lower()
                    if arg_name not in seen_args:
                        seen_args.add(arg_name)
                        arguments.append(PipeArgument(
                            name=arg_name,
                            type=arg.get('type', 'string'),
                            description=arg.get('description', ''),
                            default=arg.get('default'),
                            options=arg.get('options'),
                            required=arg.get('required', False),
                            prefix=arg.get('prefix', '—'),
                        ))
        except Exception as e:
            log.warning(f"Failed to parse PIPE_ARGUMENTS: {e}")

    # ── Strategy 2: Dict-based param_patterns ──────────────────────────
    # Detects patterns like:
    #   param_patterns = {
    #       "duration": (r"—duration\s+(\d+)", int),
    #       "sampler_name": (r"—sampler\s+(\w+)", str),
    #   }
    # or individual lines:  "duration": (r"—duration\s+(\d+)", int),
    dict_entry_pattern = re.compile(
        r'["\'](\w+)["\']\s*:\s*\(\s*r["\']'      # "param_name": (r"
        r'(?:—|--)(\w+)'                            # —flag or --flag
        r'[^"\']*["\']'                             # rest of regex string
        r'\s*,\s*(\w+)\s*\)',                       # , type)
        re.IGNORECASE,
    )
    for m in dict_entry_pattern.finditer(code):
        dict_key = m.group(1).lower()           # dict key is the internal param name
        flag_name = m.group(2).lower()          # regex flag is what the user types
        converter = m.group(3).lower()          # int / float / str
        if flag_name not in seen_args:
            seen_args.add(flag_name)
            # Also mark the dict key as seen to avoid duplicates from Strategy 3
            seen_args.add(dict_key)
            if converter in ('int', 'float'):
                arg_type = "number"
            else:
                arg_type = "string"
            # Use a friendlier description derived from the dict key
            desc = dict_key.replace('_', ' ').title() if dict_key != flag_name else f"Set {flag_name} parameter"
            arguments.append(PipeArgument(
                name=flag_name,
                type=arg_type,
                description=desc,
                prefix="—",
            ))

    # ── Strategy 3: Individual re.search / re.sub calls ────────────────
    # Broad pattern that catches any re.search(r"—flag..." or re.sub(r"—flag..."
    # regardless of what follows the flag name in the regex string.
    flag_patterns = [
        # Em-dash (—) variants
        r're\.search\s*\(\s*r["\']—(\w+)',
        r're\.sub\s*\(\s*r["\']—(\w+)',
        r're\.findall\s*\(\s*r["\']—(\w+)',
        # Double-dash (--) variants
        r're\.search\s*\(\s*r["\']--(\w+)',
        r're\.sub\s*\(\s*r["\']--(\w+)',
        r're\.findall\s*\(\s*r["\']--(\w+)',
    ]

    for pattern in flag_patterns:
        for match in re.finditer(pattern, code, re.IGNORECASE):
            arg_name = match.group(1).lower()
            if arg_name not in seen_args:
                seen_args.add(arg_name)

                full_match = match.group(0)

                # Extract just the rest of the SAME regex string after the flag name.
                # Find the closing quote of the regex string to avoid bleed from
                # other nearby patterns that would cause mis-classification.
                after_flag = code[match.end():]
                # Find the closing quote that ends this r"..." string
                close_quote = after_flag.find('"')
                close_squote = after_flag.find("'")
                if close_quote == -1:
                    close_quote = 9999
                if close_squote == -1:
                    close_squote = 9999
                end_idx = min(close_quote, close_squote)
                same_regex_rest = after_flag[:end_idx] if end_idx < 9999 else after_flag[:80]

                # Also look at the line context for int()/float() casts
                line_context = code[match.start():match.start() + 300]

                # Boolean: no value capture after the flag — regex ends right
                # after the name, or only has \b / boundary / quote
                if re.match(r'^(?:\\b)?$', same_regex_rest.strip()):
                    arg_type = "boolean"
                # Number: regex captures digits WITHIN the same regex string,
                # or there's an int()/float() cast on the same line
                elif (r'\d+' in same_regex_rest or r'[\d.]+' in same_regex_rest):
                    arg_type = "number"
                elif ('int(' in line_context.split('\n')[0] or 'float(' in line_context.split('\n')[0]):
                    arg_type = "number"
                elif r'\w+' in same_regex_rest or r'[^\s]+' in same_regex_rest:
                    arg_type = "string"
                else:
                    # Nothing meaningful after the flag name → boolean
                    arg_type = "boolean"

                prefix = "—" if "—" in full_match else "--"

                arguments.append(PipeArgument(
                    name=arg_name,
                    type=arg_type,
                    description=f"Set {arg_name} parameter",
                    prefix=prefix,
                ))

    # ── Strategy 4: Flags with prefix in a non-capturing group ─────────
    # Detects two sub-patterns where the dash prefix is wrapped in (?:...) :
    #
    # 4a – Alternation name group:
    #   re.search(r"(?:--|—|–)(?:aspect_ratio|ar)\s+(\d+:\d+)", ...)
    #
    # 4b – Bare flag name (no alternation group):
    #   re.search(r"(?:--|—|–)size\s+(\d+)[x×](\d+)", ...)

    def _infer_type_from_rest(rest: str) -> str:
        """Infer argument type from the portion of regex after the flag name."""
        if r'\d+:\d+' in rest:
            return "string"       # ratio like 16:9
        elif r'[x\xd7]' in rest or '[x×]' in rest:
            return "string"       # dimension like 1024x768
        elif r'\d+' in rest and ':' not in rest:
            return "number"
        elif r'\w+' in rest or r'[^\s]+' in rest:
            return "string"
        return "string"

    # Prefix group sub-pattern (reused by both 4a and 4b)
    prefix_group = r'\(\?:[^)]*(?:--|\u2014|\u2013)[^)]*\)'

    # 4a: prefix group + alternation name group  (?:name1|name2)
    alternation_pattern = re.compile(
        r're\.(?:search|sub|findall)\s*\(\s*r["\']'
        + prefix_group +
        r'\(\?:(\w+(?:\|\w+)*)\)'       # (?:flag1|flag2) → capture
        r'([^"\']*)["\']',              # rest of regex string
        re.IGNORECASE,
    )
    for m in alternation_pattern.finditer(code):
        names_str = m.group(1)
        rest_of_regex = m.group(2)
        names = [n.lower() for n in names_str.split('|')]
        primary_name = max(names, key=len)

        if primary_name not in seen_args:
            for n in names:
                seen_args.add(n)

            arg_type = _infer_type_from_rest(rest_of_regex)
            desc = primary_name.replace('_', ' ').title()
            aliases = [n for n in names if n != primary_name]
            if aliases:
                desc += f" (alias: {', '.join(aliases)})"

            arguments.append(PipeArgument(
                name=primary_name,
                type=arg_type,
                description=desc,
                prefix="—",
            ))

    # 4b: prefix group + bare flag name (no alternation group)
    bare_flag_pattern = re.compile(
        r're\.(?:search|sub|findall)\s*\(\s*r["\']'
        + prefix_group +
        r'(\w+)'                        # bare flag name → capture
        r'([^"\']*)["\']',              # rest of regex string
        re.IGNORECASE,
    )
    for m in bare_flag_pattern.finditer(code):
        flag_name = m.group(1).lower()
        rest_of_regex = m.group(2)

        if flag_name not in seen_args:
            seen_args.add(flag_name)
            arg_type = _infer_type_from_rest(rest_of_regex)
            desc = flag_name.replace('_', ' ').title()

            arguments.append(PipeArgument(
                name=flag_name,
                type=arg_type,
                description=desc,
                prefix="—",
            ))

    return PipeArgumentsSpec(arguments=arguments)


router = APIRouter()

############################
# GetFunctions
############################


@router.get("/", response_model=list[FunctionResponse])
async def get_functions(user=Depends(get_verified_user)):
    return Functions.get_functions()


############################
# ExportFunctions
############################


@router.get("/export", response_model=list[FunctionModel | FunctionWithValvesModel])
async def get_functions(include_valves: bool = False, user=Depends(get_admin_user)):
    return Functions.get_functions(include_valves=include_valves)


############################
# LoadFunctionFromLink
############################


class LoadUrlForm(BaseModel):
    url: HttpUrl


def github_url_to_raw_url(url: str) -> str:
    # Handle 'tree' (folder) URLs (add main.py at the end)
    m1 = re.match(r"https://github\.com/([^/]+)/([^/]+)/tree/([^/]+)/(.*)", url)
    if m1:
        org, repo, branch, path = m1.groups()
        return f"https://raw.githubusercontent.com/{org}/{repo}/refs/heads/{branch}/{path.rstrip('/')}/main.py"

    # Handle 'blob' (file) URLs
    m2 = re.match(r"https://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.*)", url)
    if m2:
        org, repo, branch, path = m2.groups()
        return (
            f"https://raw.githubusercontent.com/{org}/{repo}/refs/heads/{branch}/{path}"
        )

    # No match; return as-is
    return url


@router.post("/load/url", response_model=Optional[dict])
async def load_function_from_url(
    request: Request, form_data: LoadUrlForm, user=Depends(get_admin_user)
):
    # NOTE: This is NOT a SSRF vulnerability:
    # This endpoint is admin-only (see get_admin_user), meant for *trusted* internal use,
    # and does NOT accept untrusted user input. Access is enforced by authentication.

    url = str(form_data.url)
    if not url:
        raise HTTPException(status_code=400, detail="Please enter a valid URL")

    url = github_url_to_raw_url(url)
    url_parts = url.rstrip("/").split("/")

    file_name = url_parts[-1]
    function_name = (
        file_name[:-3]
        if (
            file_name.endswith(".py")
            and (not file_name.startswith(("main.py", "index.py", "__init__.py")))
        )
        else url_parts[-2] if len(url_parts) > 1 else "function"
    )

    try:
        async with aiohttp.ClientSession(trust_env=True) as session:
            async with session.get(
                url, headers={"Content-Type": "application/json"}
            ) as resp:
                if resp.status != 200:
                    raise HTTPException(
                        status_code=resp.status, detail="Failed to fetch the function"
                    )
                data = await resp.text()
                if not data:
                    raise HTTPException(
                        status_code=400, detail="No data received from the URL"
                    )
        return {
            "name": function_name,
            "content": data,
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error importing function: {e}")


############################
# SyncFunctions
############################


class SyncFunctionsForm(BaseModel):
    functions: list[FunctionWithValvesModel] = []


@router.post("/sync", response_model=list[FunctionWithValvesModel])
async def sync_functions(
    request: Request, form_data: SyncFunctionsForm, user=Depends(get_admin_user)
):
    try:
        for function in form_data.functions:
            function.content = replace_imports(function.content)
            function_module, function_type, frontmatter = load_function_module_by_id(
                function.id,
                content=function.content,
            )

            if hasattr(function_module, "Valves") and function.valves:
                Valves = function_module.Valves
                try:
                    Valves(
                        **{k: v for k, v in function.valves.items() if v is not None}
                    )
                except Exception as e:
                    log.exception(
                        f"Error validating valves for function {function.id}: {e}"
                    )
                    raise e

        return Functions.sync_functions(user.id, form_data.functions)
    except Exception as e:
        log.exception(f"Failed to load a function: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ERROR_MESSAGES.DEFAULT(e),
        )


############################
# CreateNewFunction
############################


@router.post("/create", response_model=Optional[FunctionResponse])
async def create_new_function(
    request: Request, form_data: FunctionForm, user=Depends(get_admin_user)
):
    if not form_data.id.isidentifier():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only alphanumeric characters and underscores are allowed in the id",
        )

    form_data.id = form_data.id.lower()

    function = Functions.get_function_by_id(form_data.id)
    if function is None:
        try:
            form_data.content = replace_imports(form_data.content)
            function_module, function_type, frontmatter = load_function_module_by_id(
                form_data.id,
                content=form_data.content,
            )
            form_data.meta.manifest = frontmatter

            FUNCTIONS = request.app.state.FUNCTIONS
            FUNCTIONS[form_data.id] = function_module

            function = Functions.insert_new_function(user.id, function_type, form_data)

            function_cache_dir = CACHE_DIR / "functions" / form_data.id
            function_cache_dir.mkdir(parents=True, exist_ok=True)

            if function_type == "filter" and getattr(function_module, "toggle", None):
                Functions.update_function_metadata_by_id(id, {"toggle": True})

            if function:
                return function
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=ERROR_MESSAGES.DEFAULT("Error creating function"),
                )
        except Exception as e:
            log.exception(f"Failed to create a new function: {e}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ERROR_MESSAGES.DEFAULT(e),
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ERROR_MESSAGES.ID_TAKEN,
        )


############################
# GetFunctionById
############################


@router.get("/id/{id}", response_model=Optional[FunctionModel])
async def get_function_by_id(id: str, user=Depends(get_admin_user)):
    function = Functions.get_function_by_id(id)

    if function:
        return function
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.NOT_FOUND,
        )


############################
# ToggleFunctionById
############################


@router.post("/id/{id}/toggle", response_model=Optional[FunctionModel])
async def toggle_function_by_id(id: str, user=Depends(get_admin_user)):
    function = Functions.get_function_by_id(id)
    if function:
        function = Functions.update_function_by_id(
            id, {"is_active": not function.is_active}
        )

        if function:
            return function
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ERROR_MESSAGES.DEFAULT("Error updating function"),
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.NOT_FOUND,
        )


############################
# ToggleGlobalById
############################


@router.post("/id/{id}/toggle/global", response_model=Optional[FunctionModel])
async def toggle_global_by_id(id: str, user=Depends(get_admin_user)):
    function = Functions.get_function_by_id(id)
    if function:
        function = Functions.update_function_by_id(
            id, {"is_global": not function.is_global}
        )

        if function:
            return function
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ERROR_MESSAGES.DEFAULT("Error updating function"),
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.NOT_FOUND,
        )


############################
# UpdateFunctionById
############################


@router.post("/id/{id}/update", response_model=Optional[FunctionModel])
async def update_function_by_id(
    request: Request, id: str, form_data: FunctionForm, user=Depends(get_admin_user)
):
    try:
        form_data.content = replace_imports(form_data.content)
        function_module, function_type, frontmatter = load_function_module_by_id(
            id, content=form_data.content
        )
        form_data.meta.manifest = frontmatter

        FUNCTIONS = request.app.state.FUNCTIONS
        FUNCTIONS[id] = function_module

        updated = {**form_data.model_dump(exclude={"id"}), "type": function_type}
        log.debug(updated)

        function = Functions.update_function_by_id(id, updated)

        if function_type == "filter" and getattr(function_module, "toggle", None):
            Functions.update_function_metadata_by_id(id, {"toggle": True})

        if function:
            return function
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ERROR_MESSAGES.DEFAULT("Error updating function"),
            )

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=ERROR_MESSAGES.DEFAULT(e),
        )


############################
# DeleteFunctionById
############################


@router.delete("/id/{id}/delete", response_model=bool)
async def delete_function_by_id(
    request: Request, id: str, user=Depends(get_admin_user)
):
    result = Functions.delete_function_by_id(id)

    if result:
        FUNCTIONS = request.app.state.FUNCTIONS
        if id in FUNCTIONS:
            del FUNCTIONS[id]

    return result


############################
# GetFunctionValves
############################


@router.get("/id/{id}/valves", response_model=Optional[dict])
async def get_function_valves_by_id(id: str, user=Depends(get_admin_user)):
    function = Functions.get_function_by_id(id)
    if function:
        try:
            valves = Functions.get_function_valves_by_id(id)
            return valves
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ERROR_MESSAGES.DEFAULT(e),
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.NOT_FOUND,
        )


############################
# GetFunctionValvesSpec
############################


@router.get("/id/{id}/valves/spec", response_model=Optional[dict])
async def get_function_valves_spec_by_id(
    request: Request, id: str, user=Depends(get_admin_user)
):
    function = Functions.get_function_by_id(id)
    if function:
        function_module, function_type, frontmatter = get_function_module_from_cache(
            request, id
        )

        if hasattr(function_module, "Valves"):
            Valves = function_module.Valves
            return Valves.schema()
        return None
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.NOT_FOUND,
        )


############################
# UpdateFunctionValves
############################


@router.post("/id/{id}/valves/update", response_model=Optional[dict])
async def update_function_valves_by_id(
    request: Request, id: str, form_data: dict, user=Depends(get_admin_user)
):
    function = Functions.get_function_by_id(id)
    if function:
        function_module, function_type, frontmatter = get_function_module_from_cache(
            request, id
        )

        if hasattr(function_module, "Valves"):
            Valves = function_module.Valves

            try:
                form_data = {k: v for k, v in form_data.items() if v is not None}
                valves = Valves(**form_data)

                valves_dict = valves.model_dump(exclude_unset=True)
                Functions.update_function_valves_by_id(id, valves_dict)
                return valves_dict
            except Exception as e:
                log.exception(f"Error updating function values by id {id}: {e}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=ERROR_MESSAGES.DEFAULT(e),
                )
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=ERROR_MESSAGES.NOT_FOUND,
            )

    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.NOT_FOUND,
        )


############################
# FunctionUserValves
############################


@router.get("/id/{id}/valves/user", response_model=Optional[dict])
async def get_function_user_valves_by_id(id: str, user=Depends(get_verified_user)):
    function = Functions.get_function_by_id(id)
    if function:
        try:
            user_valves = Functions.get_user_valves_by_id_and_user_id(id, user.id)
            return user_valves
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=ERROR_MESSAGES.DEFAULT(e),
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.NOT_FOUND,
        )


@router.get("/id/{id}/valves/user/spec", response_model=Optional[dict])
async def get_function_user_valves_spec_by_id(
    request: Request, id: str, user=Depends(get_verified_user)
):
    function = Functions.get_function_by_id(id)
    if function:
        function_module, function_type, frontmatter = get_function_module_from_cache(
            request, id
        )

        if hasattr(function_module, "UserValves"):
            UserValves = function_module.UserValves
            return UserValves.schema()
        return None
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.NOT_FOUND,
        )


@router.post("/id/{id}/valves/user/update", response_model=Optional[dict])
async def update_function_user_valves_by_id(
    request: Request, id: str, form_data: dict, user=Depends(get_verified_user)
):
    function = Functions.get_function_by_id(id)

    if function:
        function_module, function_type, frontmatter = get_function_module_from_cache(
            request, id
        )

        if hasattr(function_module, "UserValves"):
            UserValves = function_module.UserValves

            try:
                form_data = {k: v for k, v in form_data.items() if v is not None}
                user_valves = UserValves(**form_data)
                user_valves_dict = user_valves.model_dump(exclude_unset=True)
                Functions.update_user_valves_by_id_and_user_id(
                    id, user.id, user_valves_dict
                )
                return user_valves_dict
            except Exception as e:
                log.exception(f"Error updating function user valves by id {id}: {e}")
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=ERROR_MESSAGES.DEFAULT(e),
                )
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=ERROR_MESSAGES.NOT_FOUND,
            )
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=ERROR_MESSAGES.NOT_FOUND,
        )


############################
# GetPipeArguments
############################


@router.get("/id/{id}/arguments", response_model=PipeArgumentsSpec)
async def get_pipe_arguments_by_id(
    request: Request, id: str, user=Depends(get_verified_user)
):
    """
    Extract available arguments from a pipe function's code.
    This analyzes the Python code to find flag patterns that users can specify
    in their prompts (e.g., —v1, —strength=8).
    """
    function = Functions.get_function_by_id(id)
    if not function:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=ERROR_MESSAGES.NOT_FOUND,
        )
    
    if function.type != "pipe":
        return PipeArgumentsSpec(arguments=[], description="Not a pipe function")
    
    try:
        # First check if there are explicitly stored arguments in metadata
        meta = function.meta.model_dump() if hasattr(function.meta, 'model_dump') else dict(function.meta) if function.meta else {}
        if meta.get('pipe_arguments'):
            stored_args = [PipeArgument(**arg) for arg in meta['pipe_arguments']]
            return PipeArgumentsSpec(arguments=stored_args)

        # Extract arguments from the function's code
        arguments_spec = extract_pipe_arguments_from_code(function.content)
        
        # Also check if the function module has explicit PIPE_ARGUMENTS attribute
        try:
            function_module, function_type, frontmatter = get_function_module_from_cache(
                request, id
            )
            if hasattr(function_module, "PIPE_ARGUMENTS"):
                explicit_args = function_module.PIPE_ARGUMENTS
                if isinstance(explicit_args, list):
                    seen = {arg.name for arg in arguments_spec.arguments}
                    for arg in explicit_args:
                        if isinstance(arg, dict) and arg.get('name') not in seen:
                            arguments_spec.arguments.append(PipeArgument(**arg))
        except Exception as e:
            log.warning(f"Could not load function module for arguments: {e}")
        
        return arguments_spec
    except Exception as e:
        log.exception(f"Error extracting pipe arguments for {id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error extracting arguments: {str(e)}",
        )


class UpdatePipeArgumentsForm(BaseModel):
    arguments: List[PipeArgument] = []


@router.post("/id/{id}/arguments/update", response_model=PipeArgumentsSpec)
async def update_pipe_arguments_by_id(
    request: Request, id: str, form_data: UpdatePipeArgumentsForm, user=Depends(get_admin_user)
):
    """
    Update/override the pipe arguments for a function.
    This stores the arguments in the function's metadata.
    """
    function = Functions.get_function_by_id(id)
    if not function:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=ERROR_MESSAGES.NOT_FOUND,
        )
    
    if function.type != "pipe":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Not a pipe function",
        )
    
    try:
        # Store arguments in function metadata
        meta = function.meta.model_dump() if hasattr(function.meta, 'model_dump') else dict(function.meta)
        meta['pipe_arguments'] = [arg.model_dump() for arg in form_data.arguments]
        
        Functions.update_function_metadata_by_id(id, meta)
        
        return PipeArgumentsSpec(arguments=form_data.arguments)
    except Exception as e:
        log.exception(f"Error updating pipe arguments for {id}: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error updating arguments: {str(e)}",
        )
