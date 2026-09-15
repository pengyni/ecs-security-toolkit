@echo off
setlocal
set ROOT=%~dp0
python "%ROOT%ecs-audit.py" %*
