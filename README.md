# Secure File Transfer

A secure file sharing application with end-to-end encryption and one-time access codes.

## Features

- 🔒 **End-to-end encryption** using Fernet symmetric encryption
- 🎨 **Beautiful green gradient UI** with smooth animations
- ⏰ **24-hour auto-deletion** for enhanced security
- 📱 **Responsive design** that works on all devices
- 🚀 **Serverless deployment** ready for Vercel
- 🔐 **One-time access codes** for maximum security

## Tech Stack

- **Backend**: Python Flask
- **Frontend**: HTML, CSS, JavaScript
- **Encryption**: Cryptography library with PBKDF2 key derivation
- **Deployment**: Vercel (serverless)

## Local Development

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
python server.py
```

3. Open your browser and visit `http://localhost:5001`

## Deployment to Vercel

### Method 1: Deploy via GitHub (Recommended)

1. **Push to GitHub**:
   - Create a new repository on GitHub
   - Push this code to your repository

2. **Deploy on Vercel**:
   - Go to [vercel.com](https://vercel.com)
   - Sign up/login with your GitHub account
   - Click "New Project"
   - Import your GitHub repository
   - Vercel will auto-detect the Python configuration
   - Click "Deploy"

### Method 2: Deploy via Vercel CLI

1. Install Vercel CLI:
```bash
npm i -g vercel
```

2. Deploy:
```bash
vercel
```

## File Structure

```
├── api/
│   └── index.py          # Vercel serverless function
├── templates/
│   └── index.html        # Main application UI
├── vercel.json           # Vercel configuration
├── requirements.txt      # Python dependencies
├── server.py            # Local development server
└── README.md            # This file
```

## Security Features

- **PBKDF2 Key Derivation**: 100,000 iterations with salt
- **Fernet Encryption**: AES 128 in CBC mode
- **Rate Limiting**: Prevents abuse
- **Auto-cleanup**: Files deleted after 24 hours
- **One-time access**: Codes work only once

## Usage

1. **Upload**: Select a file and click "Encrypt & Upload"
2. **Share**: Give the recipient the 6-character access code and PIN
3. **Download**: Enter the code and PIN to decrypt and download

## Environment Variables

For production deployment, you can set these environment variables:

- `MAX_CONTENT_LENGTH`: Maximum file size (default: 150MB)
- `UPLOAD_FOLDER`: Directory for temporary files (default: uploads/)

## License

MIT License - feel free to use this project for personal or commercial purposes.
