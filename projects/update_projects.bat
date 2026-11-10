@echo off
echo Updating project submodules...
git submodule update --remote --merge

echo Staging changes...
git add .

echo Committing and pushing to portfolio...
git commit -m "Update project submodule to latest commit"
git push origin main

echo Done!
pause
