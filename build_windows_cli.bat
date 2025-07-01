@echo off
echo DMA检测工具 (命令行版) 打包脚本 - MantraI@MantraChen
echo =====================================

echo 检查Python环境...
python --version
if not %errorlevel% == 0 (
    echo 错误: 未找到Python，请先安装Python 3.7+ 并确保已添加到系统环境变量PATH中。
    pause
    exit /b 1
)

echo.
echo 安装或更新依赖包...
pip install psutil pyinstaller
if not %errorlevel% == 0 (
    echo 错误: 依赖包安装失败，请检查网络连接或pip配置。
    pause
    exit /b 1
)

echo.
echo 开始打包...
pyinstaller --onefile --console --name "DMA_Detector_CLI_MantraI" --version-file version_info.txt dma_detector_cli.py

if not %errorlevel% == 0 (
    echo.
    echo 打包失败，请检查错误信息。
    pause
) else (
    echo.
    echo 打包成功！
    echo 可执行文件位置: dist\DMA_Detector_CLI_MantraI.exe
    echo.
    echo 按任意键打开输出目录...
    pause >nul
    explorer dist
)
