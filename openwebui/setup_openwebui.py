#!/usr/bin/env python3
"""
Open WebUI Local Development Setup Script for Windows
Automates the setup process described in the Open WebUI development guide
"""

import os
import sys
import subprocess
import shutil
import time
import threading
from pathlib import Path
import requests
import json

class Colors:
    """ANSI color codes for terminal output"""
    RED = ''
    GREEN = ''
    YELLOW = ''
    BLUE = ''
    PURPLE = ''
    CYAN = ''
    WHITE = ''
    BOLD = ''
    END = ''

class OpenWebUISetup:
    def __init__(self):
        self.project_dir = None
        self.frontend_process = None
        self.backend_process = None
        
    def print_colored(self, message, color=Colors.WHITE):
        """Print colored message to console"""
        print(f"{color}{message}{Colors.END}")
        
    def print_header(self, message):
        """Print a header message"""
        self.print_colored(f"\n{'='*60}", Colors.CYAN)
        self.print_colored(f"{message}", Colors.CYAN + Colors.BOLD)
        self.print_colored(f"{'='*60}", Colors.CYAN)
        
    def run_command(self, command, cwd=None, shell=True, check=True):
        """Run a system command with error handling"""
        try:
            self.print_colored(f"Running: {command}", Colors.YELLOW)
            result = subprocess.run(
                command, 
                cwd=cwd, 
                shell=shell, 
                check=check,
                capture_output=True,
                text=True
            )
            if result.stdout:
                print(result.stdout)
            return result
        except subprocess.CalledProcessError as e:
            self.print_colored(f"Error running command: {command}", Colors.RED)
            self.print_colored(f"Error: {e.stderr}", Colors.RED)
            if check:
                raise
            return None
            
    def check_prerequisites(self):
        """Check if required tools are installed"""
        self.print_header("CHECKING PREREQUISITES")
        
        # Check Python version
        python_version = sys.version_info
        if python_version < (3, 11):
            self.print_colored(f"❌ Python 3.11+ required. Current: {python_version.major}.{python_version.minor}", Colors.RED)
            return False
        else:
            self.print_colored(f"✅ Python {python_version.major}.{python_version.minor}.{python_version.micro}", Colors.GREEN)
            
        # Check Git
        try:
            result = self.run_command("git --version", check=False)
            if result and result.returncode == 0:
                self.print_colored("✅ Git is installed", Colors.GREEN)
            else:
                self.print_colored("❌ Git not found. Please install Git.", Colors.RED)
                return False
        except:
            self.print_colored("❌ Git not found. Please install Git.", Colors.RED)
            return False
            
        # Check Node.js
        try:
            result = self.run_command("node --version", check=False)
            if result and result.returncode == 0:
                version_str = result.stdout.strip()
                # Extract version number (remove 'v' prefix)
                version_parts = version_str[1:].split('.')
                major_version = int(version_parts[0])
                if major_version >= 22:
                    self.print_colored(f"✅ Node.js {version_str}", Colors.GREEN)
                else:
                    self.print_colored(f"❌ Node.js 22.10+ required. Current: {version_str}", Colors.RED)
                    return False
            else:
                self.print_colored("❌ Node.js not found. Please install Node.js 22.10+", Colors.RED)
                return False
        except:
            self.print_colored("❌ Node.js not found. Please install Node.js 22.10+", Colors.RED)
            return False
            
        # Check npm
        try:
            result = self.run_command("npm --version", check=False)
            if result and result.returncode == 0:
                self.print_colored(f"✅ npm {result.stdout.strip()}", Colors.GREEN)
            else:
                self.print_colored("❌ npm not found", Colors.RED)
                return False
        except:
            self.print_colored("❌ npm not found", Colors.RED)
            return False
            
        # Check if conda is available (optional)
        try:
            result = self.run_command("conda --version", check=False)
            if result and result.returncode == 0:
                self.print_colored(f"✅ Conda {result.stdout.strip()} (recommended for Python environment)", Colors.GREEN)
                self.has_conda = True
            else:
                self.print_colored("⚠️ Conda not found (optional but recommended)", Colors.YELLOW)
                self.has_conda = False
        except:
            self.print_colored("⚠️ Conda not found (optional but recommended)", Colors.YELLOW)
            self.has_conda = False
            
        return True
        
    def clone_repository(self):
        """Clone the Open WebUI repository"""
        self.print_header("CLONING REPOSITORY")
        
        # Ask user for installation directory
        while True:
            install_dir = input("Enter installation directory (default: current directory): ").strip()
            if not install_dir:
                install_dir = os.getcwd()
            
            install_path = Path(install_dir)
            if not install_path.exists():
                try:
                    install_path.mkdir(parents=True)
                    break
                except Exception as e:
                    self.print_colored(f"Error creating directory: {e}", Colors.RED)
                    continue
            else:
                break
                
        self.project_dir = install_path / "open-webui"
        
        # Check if directory already exists
        if self.project_dir.exists():
            self.print_colored(f"Directory {self.project_dir} already exists!", Colors.YELLOW)
            choice = input("Do you want to (1) use existing directory, (2) delete and re-clone, or (3) exit? [1/2/3]: ").strip()
            
            if choice == "2":
                shutil.rmtree(self.project_dir)
                self.print_colored("Deleted existing directory", Colors.YELLOW)
            elif choice == "3":
                sys.exit(0)
            elif choice != "1":
                self.print_colored("Invalid choice. Exiting.", Colors.RED)
                sys.exit(1)
                
        if not self.project_dir.exists():
            self.run_command(f"git clone https://github.com/open-webui/open-webui.git", cwd=install_path)
            
        self.print_colored(f"✅ Repository ready at: {self.project_dir}", Colors.GREEN)
        
    def setup_frontend(self):
        """Setup frontend environment"""
        self.print_header("SETTING UP FRONTEND")
        
        # Copy environment file
        env_example = self.project_dir / ".env.example"
        env_file = self.project_dir / ".env"
        
        if env_example.exists() and not env_file.exists():
            shutil.copy2(env_example, env_file)
            self.print_colored("✅ Created .env file from .env.example", Colors.GREEN)
        elif env_file.exists():
            self.print_colored("✅ .env file already exists", Colors.GREEN)
        else:
            self.print_colored("⚠️ .env.example not found, skipping .env creation", Colors.YELLOW)
            
        # Install dependencies
        self.print_colored("Installing frontend dependencies...", Colors.BLUE)
        try:
            # Set NODE_OPTIONS to prevent heap limit errors
            env = os.environ.copy()
            env['NODE_OPTIONS'] = '--max-old-space-size=4096'
            
            result = subprocess.run(
                "npm install", 
                cwd=self.project_dir,
                shell=True,
                env=env,
                check=False
            )
            
            if result.returncode != 0:
                self.print_colored("npm install failed, trying with --force", Colors.YELLOW)
                subprocess.run(
                    "npm install --force", 
                    cwd=self.project_dir,
                    shell=True,
                    env=env,
                    check=True
                )
                
        except subprocess.CalledProcessError as e:
            self.print_colored(f"Frontend setup failed: {e}", Colors.RED)
            return False
            
        # Build frontend
        self.print_colored("Building frontend...", Colors.BLUE)
        try:
            env = os.environ.copy()
            env['NODE_OPTIONS'] = '--max-old-space-size=4096'
            
            subprocess.run(
                "npm run build",
                cwd=self.project_dir,
                shell=True,
                env=env,
                check=True
            )
            self.print_colored("✅ Frontend build completed", Colors.GREEN)
        except subprocess.CalledProcessError as e:
            self.print_colored(f"Frontend build failed: {e}", Colors.YELLOW)
            
        return True
        
    def setup_backend(self):
        """Setup backend environment"""
        self.print_header("SETTING UP BACKEND")
        
        backend_dir = self.project_dir / "backend"
        
        if not backend_dir.exists():
            self.print_colored("❌ Backend directory not found!", Colors.RED)
            return False
            
        # Setup Python environment
        if hasattr(self, 'has_conda') and self.has_conda:
            self.print_colored("Setting up Conda environment...", Colors.BLUE)
            try:
                # Create conda environment
                self.run_command("conda create --name open-webui python=3.11 -y")
                self.print_colored("✅ Conda environment 'open-webui' created", Colors.GREEN)
                
                # Note about activation
                self.print_colored("ℹ️ Conda environment created. You'll need to activate it manually when running the backend.", Colors.BLUE)
                self.print_colored("Run: conda activate open-webui", Colors.CYAN)
                
            except subprocess.CalledProcessError as e:
                self.print_colored(f"Conda environment creation failed: {e}", Colors.YELLOW)
                self.print_colored("Continuing with system Python...", Colors.YELLOW)
        
        # Install backend dependencies
        requirements_file = backend_dir / "requirements.txt"
        if requirements_file.exists():
            self.print_colored("Installing backend dependencies...", Colors.BLUE)
            try:
                # Try to install in the current Python environment
                self.run_command(f"pip install -r {requirements_file} -U")
                self.print_colored("✅ Backend dependencies installed", Colors.GREEN)
            except subprocess.CalledProcessError as e:
                self.print_colored(f"Backend dependency installation failed: {e}", Colors.RED)
                return False
        else:
            self.print_colored("❌ requirements.txt not found in backend directory", Colors.RED)
            return False
            
        return True
        
    def check_ports(self):
        """Check if required ports are available"""
        self.print_header("CHECKING PORTS")
        
        def is_port_in_use(port):
            import socket
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                return s.connect_ex(('localhost', port)) == 0
                
        frontend_port = 5173
        backend_port = 8080
        
        if is_port_in_use(frontend_port):
            self.print_colored(f"⚠️ Port {frontend_port} is already in use", Colors.YELLOW)
            return False
        else:
            self.print_colored(f"✅ Port {frontend_port} is available", Colors.GREEN)
            
        if is_port_in_use(backend_port):
            self.print_colored(f"⚠️ Port {backend_port} is already in use", Colors.YELLOW)
            return False
        else:
            self.print_colored(f"✅ Port {backend_port} is available", Colors.GREEN)
            
        return True
        
    def start_services(self):
        """Start frontend and backend services"""
        self.print_header("STARTING SERVICES")
        
        if not self.check_ports():
            self.print_colored("Port conflicts detected. Please resolve before continuing.", Colors.RED)
            choice = input("Continue anyway? [y/N]: ").strip().lower()
            if choice != 'y':
                return False
                
        # Create batch files for easy service management
        self.create_batch_files()
        
        self.print_colored("Services are ready to start!", Colors.GREEN)
        self.print_colored("\nTo start the services:", Colors.CYAN)
        self.print_colored(f"1. Frontend: Run 'start_frontend.bat' in {self.project_dir}", Colors.CYAN)
        self.print_colored(f"2. Backend: Run 'start_backend.bat' in {self.project_dir}", Colors.CYAN)
        
        # Ask if user wants to start services now
        choice = input("\nWould you like to start the services now? [y/N]: ").strip().lower()
        if choice == 'y':
            self.start_services_now()
            
        return True
        
    def create_batch_files(self):
        """Create Windows batch files for starting services"""
        
        # Frontend batch file
        frontend_batch = self.project_dir / "start_frontend.bat"
        with open(frontend_batch, 'w') as f:
            f.write("@echo off\n")
            f.write("echo Starting Open WebUI Frontend...\n")
            f.write("set NODE_OPTIONS=--max-old-space-size=4096\n")
            f.write("npm run dev\n")
            f.write("pause\n")
            
        # Backend batch file
        backend_batch = self.project_dir / "start_backend.bat"
        with open(backend_batch, 'w') as f:
            f.write("@echo off\n")
            f.write("echo Starting Open WebUI Backend...\n")
            f.write("cd backend\n")
            if hasattr(self, 'has_conda') and self.has_conda:
                f.write("echo Activating conda environment...\n")
                f.write("call conda activate open-webui\n")
            f.write("echo Starting backend server...\n")
            f.write("python -m uvicorn main:app --host 0.0.0.0 --port 8080 --reload\n")
            f.write("pause\n")
            
        # Combined batch file
        combined_batch = self.project_dir / "start_openwebui.bat"
        with open(combined_batch, 'w') as f:
            f.write("@echo off\n")
            f.write("echo Starting Open WebUI (Frontend + Backend)...\n")
            f.write("echo.\n")
            f.write("echo Starting Backend...\n")
            f.write("start cmd /k \"cd backend && ")
            if hasattr(self, 'has_conda') and self.has_conda:
                f.write("conda activate open-webui && ")
            f.write("python -m uvicorn main:app --host 0.0.0.0 --port 8080 --reload\"\n")
            f.write("timeout /t 5 /nobreak\n")
            f.write("echo.\n")
            f.write("echo Starting Frontend...\n")
            f.write("set NODE_OPTIONS=--max-old-space-size=4096\n")
            f.write("start cmd /k \"npm run dev\"\n")
            f.write("echo.\n")
            f.write("echo Open WebUI is starting...\n")
            f.write("echo Frontend will be available at: http://localhost:5173\n")
            f.write("echo Backend API docs at: http://localhost:8080/docs\n")
            f.write("timeout /t 10\n")
            f.write("start http://localhost:5173\n")
            
        self.print_colored("✅ Created batch files for easy service management", Colors.GREEN)
        
    def start_services_now(self):
        """Start services immediately"""
        import webbrowser
        
        self.print_colored("Starting services...", Colors.BLUE)
        
        try:
            # Start backend
            backend_dir = self.project_dir / "backend"
            backend_cmd = "python -m uvicorn main:app --host 0.0.0.0 --port 8080 --reload"
            
            self.backend_process = subprocess.Popen(
                backend_cmd,
                cwd=backend_dir,
                shell=True,
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
            
            time.sleep(3)  # Give backend time to start
            
            # Start frontend
            frontend_cmd = "npm run dev"
            env = os.environ.copy()
            env['NODE_OPTIONS'] = '--max-old-space-size=4096'
            
            self.frontend_process = subprocess.Popen(
                frontend_cmd,
                cwd=self.project_dir,
                shell=True,
                env=env,
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
            
            time.sleep(5)  # Give frontend time to start
            
            self.print_colored("✅ Services started!", Colors.GREEN)
            self.print_colored("Frontend: http://localhost:5173", Colors.CYAN)
            self.print_colored("Backend API: http://localhost:8080/docs", Colors.CYAN)
            
            # Open browser
            choice = input("Open browser to http://localhost:5173? [y/N]: ").strip().lower()
            if choice == 'y':
                webbrowser.open('http://localhost:5173')
                
        except Exception as e:
            self.print_colored(f"Error starting services: {e}", Colors.RED)
            
    def print_success_message(self):
        """Print final success message with instructions"""
        self.print_header("SETUP COMPLETE! 🎉")
        
        self.print_colored("Open WebUI development environment is ready!", Colors.GREEN + Colors.BOLD)
        self.print_colored(f"\nProject location: {self.project_dir}", Colors.CYAN)
        
        self.print_colored("\n📋 Next Steps:", Colors.BLUE + Colors.BOLD)
        self.print_colored("1. Navigate to your project directory:", Colors.WHITE)
        self.print_colored(f"   cd {self.project_dir}", Colors.CYAN)
        
        self.print_colored("\n2. Start the services using batch files:", Colors.WHITE)
        self.print_colored("   • Double-click 'start_openwebui.bat' (starts both)", Colors.CYAN)
        self.print_colored("   • Or run 'start_frontend.bat' and 'start_backend.bat' separately", Colors.CYAN)
        
        self.print_colored("\n3. Access the application:", Colors.WHITE)
        self.print_colored("   • Frontend: http://localhost:5173", Colors.CYAN)
        self.print_colored("   • Backend API: http://localhost:8080/docs", Colors.CYAN)
        
        if hasattr(self, 'has_conda') and self.has_conda:
            self.print_colored("\n4. For manual backend startup:", Colors.WHITE)
            self.print_colored("   conda activate open-webui", Colors.CYAN)
            self.print_colored("   cd backend", Colors.CYAN)
            self.print_colored("   python -m uvicorn main:app --host 0.0.0.0 --port 8080 --reload", Colors.CYAN)
            
        self.print_colored("\n🛠️ Development Tips:", Colors.BLUE + Colors.BOLD)
        self.print_colored("• Hot reload is enabled for both frontend and backend", Colors.WHITE)
        self.print_colored("• Make changes to code and see them instantly", Colors.WHITE)
        self.print_colored("• Check console output for any errors", Colors.WHITE)
        self.print_colored("• Use VS Code with the integrated terminal for the best experience", Colors.WHITE)
        
        self.print_colored("\n🤝 Contributing:", Colors.BLUE + Colors.BOLD)
        self.print_colored("• Create a new branch for your changes", Colors.WHITE)
        self.print_colored("• Make small, focused commits", Colors.WHITE)
        self.print_colored("• Submit pull requests to the 'dev' branch", Colors.WHITE)
        
        self.print_colored("\nHappy coding! 🚀", Colors.GREEN + Colors.BOLD)
        
    def cleanup(self):
        """Cleanup processes on exit"""
        if self.frontend_process:
            self.frontend_process.terminate()
        if self.backend_process:
            self.backend_process.terminate()
            
    def run(self):
        """Main setup process"""
        try:
            self.print_colored("🚀 Open WebUI Development Setup for Windows", Colors.BLUE + Colors.BOLD)
            self.print_colored("This script will set up your local development environment\n", Colors.WHITE)
            
            # Check prerequisites
            if not self.check_prerequisites():
                self.print_colored("\n❌ Prerequisites not met. Please install missing components and try again.", Colors.RED)
                return False
                
            # Clone repository
            self.clone_repository()
            
            # Setup frontend
            if not self.setup_frontend():
                self.print_colored("\n❌ Frontend setup failed.", Colors.RED)
                return False
                
            # Setup backend
            if not self.setup_backend():
                self.print_colored("\n❌ Backend setup failed.", Colors.RED)
                return False
                
            # Start services
            self.start_services()
            
            # Print success message
            self.print_success_message()
            
            return True
            
        except KeyboardInterrupt:
            self.print_colored("\n\n⚠️ Setup interrupted by user", Colors.YELLOW)
            return False
        except Exception as e:
            self.print_colored(f"\n❌ Unexpected error: {e}", Colors.RED)
            return False
        finally:
            self.cleanup()

def main():
    """Main entry point"""
    setup = OpenWebUISetup()
    success = setup.run()
    
    if success:
        input("\nPress Enter to exit...")
    else:
        input("\nSetup failed. Press Enter to exit...")
        sys.exit(1)

if __name__ == "__main__":
    main()