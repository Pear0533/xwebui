@echo off

if not exist "node_modules" (
    echo node_modules not found. Running npm install --force...
    npm install --force
    if errorlevel 1 (
        echo npm install failed. Exiting...
        pause
        exit /b 1
    )
    echo npm install completed successfully.
    npm run dev
) else (
    echo node_modules found. Skipping installation.
    npm run dev
)
