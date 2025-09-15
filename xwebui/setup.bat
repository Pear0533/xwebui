@echo off
copy .env.example .env
robocopy .\static .\backend\open_webui\static /E
cd backend
mkdir data
cd ..

if not exist "node_modules" (
    echo node_modules not found. Running npm install --force...
    npm install --force
    if errorlevel 1 (
        echo npm install failed. Exiting...
        pause
        exit /b 1
    )
    echo npm install completed successfully.
    npm run build
) else (
    echo node_modules found. Skipping installation.
    npm run build
)
