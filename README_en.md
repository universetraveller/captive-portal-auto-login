# captive-portal-auto-login
Runs as a daemon to monitor the captive portal and auto-login if offline, supporting multiple network interfaces.

[简体中文](./README.md) | [English (translated by ChatGPT)](./README_en.md)

The English version is translated by ChatGPT.

## Features
Periodically checks the online status and automatically logs in to networks requiring authentication. It supports connecting through a specified network interface, making it suitable for devices with multiple network cards, headless setups, or embedded systems. This solves the challenge of automatic authentication across multiple network segments.

Only Python is required, with no additional dependencies. Some runtime modifications have been made to `urllib` to support specifying the source address and network interface.

Runs in daemon mode (user-specified), with configuration stored in a module. The system can interact with the core via runtime commands and supports basic OTP authentication and encryption.

Object-oriented design, with reusable components.

## Basic Usage
All configurations can be set in [login_config](./captive-portal-auto-login/login_config.py), primarily for the login URL, username, and password. It is recommended to use the encrypted version of the password and set the encryption option to true: 
```python
DEFAULT_PASSWORD_ENCRYPTED = 'true'
```
The encryption method depends on the authentication system (e.g., WHU's campus network uses RSA encryption of a string combining the MAC address and password). You can obtain the encrypted password and algorithm from the network's debug mode and then fill in the configuration.

The included implementation is for automatic login to WHU’s campus network (RG-SMP). In theory, it is applicable to all Ruijie authentication systems (look for keywords like ruijie, eportal in the source code). It has only been tested on WHU’s network combined with the School of Computer Science network. The login process is not tied to Ruijie and can be replaced by another implementation (in the `login` function of login.py).

Start daemon: 
```bash
python3 login.py -d
```
or 
```bash
nohup python3 login.py -d 2>&1 > /dev/null &
```
You can specify the daemon socket address, port, generated file paths, etc. After starting, two files will be generated: the daemon identifier file and the OTP key file, which are automatically cleaned up upon daemon exit.

Communicate with the daemon: 
```bash
python3 login.py -m message
```
You can specify the daemon and key (via the daemon ID file and key file or by directly inputting the key). You can view and modify various parameters in real-time. Available commands are in the `init_daemon_commands` function in `login.py` (or by sending `help [command]`). Some parameter changes require reinitializing the daemon’s variables to take effect.

## Authentication Mechanism
Upon receiving an external connection, the daemon first checks the SHA-256 hash of the received key. If the key is correct, it accepts the encrypted message and decrypts it using its own key. After receiving, the key is regenerated, meaning each key is used only once for encrypting files, providing a level of security.

Since only the Python standard library is used, and no complex encryption algorithms are employed, information is encrypted using XOR encryption with a 32-bit key. Therefore, there is some risk, and it is recommended to bind the daemon to localhost (the default setting) to avoid attacks. The encryption implementation can be found in [crypt_utils](./captive-portal-auto-login/crypt_utils.py).

## Login Mechanism
Each login checks if the system is online. If not, the login function is executed. The login function posts the configured information to the gateway for authentication, and upon completion, checks the online status to confirm success.

The online check implementation is in [detectors](./captive-portal-auto-login/detectors.py), primarily using requests to the captive gateway and inspecting the response. By default, three detector groups are provided for different scenarios.

## urllib Hacking
Python's standard `urllib` does not support binding the source address and network interface. This behavior can be modified by creating a custom opener and adjusting the socket creation function. After calling `login.init()`, `urllib` will use the source address specified in the configuration, supporting interface names, IP/port combinations, and `None`.

## Legal Disclaimer
This project is merely a framework for automating operations and is not affiliated with any specific authentication system. The login process mimics the same steps a human would take when manually logging in through a browser.

All knowledge, data, code, and procedures involved in this project are sourced from legally accessible and publicly available resources. The operations performed in this project are strictly limited to sending HTTP requests to specified addresses and do not involve hacking, bypassing security measures, or compromising any computer systems, networks, or software.

The default implementation of this project is for demonstration and testing purposes only. All target addresses are publicly available, and all operations follow standard, legal authentication processes, causing no harm or infringement to the owners, copyright holders, or users of any authentication system.

The use of this project for any illegal purposes is strictly prohibited. Users must ensure that the use of this project does not infringe on the legal rights of others or cause harm to their interests.

The project assumes no responsibility for any consequences arising from the use of this project. Users are solely responsible for any outcomes resulting from their use.
