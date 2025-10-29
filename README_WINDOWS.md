# ChatGPT_arduinoV2 — Windows Installation Guide

This guide walks through setting up **ChatGPT_arduinoV2** on Windows 10/11. The project requires Python 3.13.3 or earlier (not newer), and Node.js 18+.

---

## Prerequisites

- **Windows 10 or 11** (64-bit recommended)
- **Administrator access** (for some installations)
- **Internet connection**

---

## Step 1: Install Python 3.13.3

### Option A: Direct Download (Recommended for beginners)

1. Go to [python.org/downloads](https://www.python.org/downloads/release/python-3133/)
2. Download **Windows installer (64-bit)** — `python-3.13.3-amd64.exe`
3. Run the installer:
   - ✅ **Check "Add Python to PATH"** (critical)
   - ✅ Check "Install pip"
   - ✅ Check "Install tcl/tk and IDLE"
   - Click **Install Now**
4. Verify installation in Command Prompt (cmd):
   ```cmd
   python --version
   # Expected: Python 3.13.3
   ```

### Option B: Chocolatey (if installed)

```cmd
choco install python313
```

### Option C: Windows Package Manager (winget)

```cmd
winget install Python.Python.3.13
```

---

## Step 2: Install Node.js 18+

1. Go to [nodejs.org](https://nodejs.org) and download **LTS** version (18.x or later)
2. Run the installer and follow defaults
3. Verify installation in Command Prompt:
   ```cmd
   node --version
   npm --version
   ```

---

## Step 3: Install Git for Windows

1. Go to [git-scm.com](https://git-scm.com/download/win)
2. Download and run the installer
3. Use default options (or Git Bash if you prefer a Unix-like terminal)

---

## Step 4: Clone the Repository

Open **Command Prompt** (cmd) or **Git Bash** and run:

```cmd
git clone https://github.com/IAD-ZHDK/ChatGPT_arduinoV2.git
cd ChatGPT_arduinoV2
```

---

## Step 5: Install Node.js Dependencies

From the project root (ChatGPT_arduinoV2 folder):

```cmd
npm install
```

---

## Step 6: Set Up Python Virtual Environment

**Important:** This project requires **Python 3.13.3 or earlier**. Do NOT use Python 3.14+.

### Create Virtual Environment

```cmd
# Create venv with Python 3.13
python -m venv python/venv

# Activate venv
python/venv/Scripts/activate
# (Your command prompt should now show (venv) at the start)
```

### Install Python Packages

While the venv is activated, run:

```cmd
# Upgrade pip and install build tools
python -m pip install --upgrade pip wheel setuptools

# Install core packages
python -m pip install vosk numpy piper-tts pyusb sounddevice requests

# Install from requirements file
python -m pip install --no-deps -r python/requirements.txt

# Install optional packages
python -m pip install pyaudio webrtcvad

# onnxruntime: try to install, but don't fail if unavailable
python -m pip install onnxruntime || echo "onnxruntime not available for this Python version"
```

**Notes:**
- If `piper-tts` installation fails due to espeak-ng data issues, try:
  ```cmd
  pip uninstall piper-tts -y
  pip install piper-tts --force-reinstall --no-cache-dir
  ```
- If `pyaudio` fails, you may need to install [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/).

---

## Step 7: Create and Configure .env File

Create a `.env` file in the project root with your OpenAI API key:

```cmd
# Open Notepad to create .env
notepad .env
```

Add this line and save:

```
OPENAI_API_KEY='your-openai-api-key-here'
```

Replace `your-openai-api-key-here` with your actual API key from [platform.openai.com](https://platform.openai.com/account/api-keys).

---

## Step 8: Start the Application

### Using Automated Script

From Command Prompt (or Git Bash), make `run.sh` executable and run it (requires Git Bash or WSL):

```bash
chmod +x run.sh
./run.sh
```

### Manual Start

1. Activate the Python venv (if not already):
   ```cmd
   python/venv/Scripts/activate
   ```

2. Start the application:
   ```cmd
   npm start
   ```
   or for development with auto-reload:
   ```cmd
   npm run dev
   ```

3. Open a browser and navigate to:
   - **Frontend:** http://localhost:5173
   - **Backend API:** http://localhost:3000

---

## Step 9: Verify Everything Works

### Test the Backend (WebSocket)

1. Install wscat globally (if not already):
   ```cmd
   npm install -g wscat
   ```

2. Open a new Command Prompt and connect to the WebSocket:
   ```cmd
   wscat -c ws://localhost:3000
   ```

3. Send a test message:
   ```json
   {"command":"sendMessage","message":"Hello from Windows!"}
   ```

### Test Python Imports

With the venv activated, run:

```cmd
python -c "import vosk, numpy, sounddevice; print('✓ All imports OK')"
```

---

## Troubleshooting

### Python Not Found / "python is not recognized"

**Solution:** Reinstall Python and ensure "Add Python to PATH" is checked during installation.

### pip or venv Not Found

**Solution:** Reinstall Python with pip and venv options enabled.

### Port 3000 or 5173 Already in Use

**Solution:** Kill the process using the port or change ports in `config.js` / `vite.config.js`.

On Windows, find and kill:
```cmd
netstat -ano | findstr :3000
taskkill /PID <PID> /F
```

### piper-tts espeak-ng Error

**Solution:** Reinstall piper-tts without cache:
```cmd
pip uninstall piper-tts -y
pip cache purge
pip install piper-tts --force-reinstall --no-cache-dir
```

If still failing, try conda (see below).

### pyaudio Installation Fails

**Solution:** Install [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) and retry:
```cmd
pip install pyaudio
```

### Still Having Issues? Use Conda/Miniforge

Conda often handles compiled dependencies better on Windows:

1. Download and install [Miniforge](https://github.com/conda-forge/miniforge/releases) (Windows installer)
2. Open Miniforge Prompt and run:
   ```cmd
   conda create -n chatgpt_arduino python=3.13 -y
   conda activate chatgpt_arduino
   conda install -c conda-forge piper-tts onnxruntime pyaudio
   python -m pip install -r python/requirements.txt
   ```

---

## Running at Startup (Windows)

To auto-start the application when Windows boots:

1. Create a batch file `start_chatgpt_arduino.bat`:
   ```batch
   @echo off
   cd /d "C:\path\to\ChatGPT_arduinoV2"
   call python\venv\Scripts\activate
   npm start
   pause
   ```

2. Move it to `C:\Users\<YourUsername>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`

---

## Development

### Run in Development Mode (Auto-Reload)

```cmd
npm run dev
```

This will watch for file changes and auto-reload the frontend.

### View Logs

Backend logs appear in the terminal where `npm start` was run.

For persistent logs, redirect to a file:
```cmd
npm start > logs.txt 2>&1
```

### Debugging Python Scripts

Activate venv and run directly:
```cmd
python python/scriptSTT.py
python python/scriptTTS.py
```

---

## Next Steps

- Refer to the main [README.md](README.md) for general configuration and usage instructions.
- See [config.js](config.js) for model selection and voice settings.
- Check the [Arduino examples](ArduinoExample/) for hardware integration examples.

---

## Support

For issues specific to Windows, open an issue on [GitHub](https://github.com/IAD-ZHDK/ChatGPT_arduinoV2/issues).

