# captive-portal-auto-login
Runs as a daemon to monitor the captive portal and auto-login if offline, supporting multiple network interfaces.

[简体中文](./README.md) | [English (translated by ChatGPT)](./README_en.md)

## Features
定期检测在线状态并自动登录需要进行认证的网络，支持指定网卡进行连接，适用于多网卡，无图形界面或嵌入式设备的场景。解决了多网段下自动认证的难点。

仅需安装python，无需其他依赖，实现上对urllib进行了一些运行时改动使其支持指定发送源和多网卡。

以守护进程模式运行（需用户指定），配置存储在一个module中并可以通过运行时发送指令与核心进行交互，有基础的OTP认证和加密。

面向对象设计，各组件可重用。

## 基础使用
所有配置都可以通过[login_config](./captive-portal-auto-login/login_config.py)进行设置，主要设置登录网址，账号和密码，密码推荐使用加密后的版本并设置密码加密选项为真，即```DEFAULT_PASSWORD_ENCRYPTED = 'true'```，密码的加密与具体的认证系统有关（例如WHU校园网的认证系统是对MAC地址和密码的组合字符串用一个简单的公钥进行RSA加密），可以先从认证网站的debug模式获取加密的密码和算法再填写到配置中。

自带的实现是WHU校园网认证（RG-SMP）的自动登录，理论上适用于所有锐捷认证系统（有的看不出来，但可以从认证网站的源代码或者管理系统找到ruijie，eportal等关键词），仅在武汉大学校园网加上计算机学院网络同时存在的情况下测试。登录的操作与锐捷系统无关，可替换为其他实现（login.py中的login函数）。

开启daemon：```python3 login.py -d```或```nohup python3 login.py -d 2>&1 > /dev/null &```，可以通过参数指定daemon socket的地址，端口，生成的文件地址等。启动之后会生成两个文件，daemon标识文件和OTP密钥文件，退出daemon后会自动清除。

与daemon通信：```python3 login.py -m message```，可以通过参数指定需要通信的daemon和密钥（通过指定daemon标识文件和密钥文件或者直接输入密钥），可以实时查看和修改各种参数，可用的命令在login.py的init_daemon_commands函数中（或发送help [command]查看）。部分参数修改后不能立即生效，要发送命令让daemon强制重新初始化参数相关的变量才可生效。

## 认证机制
接收到外部连接时，daemon首先检查收到的密钥的SHA-256哈希值，如果密钥正确，接收该密钥加密的信息并用自己的密钥解密，接收完成后会重新生成密钥。这种方式下密钥仅被使用一次用于加密文件，具有一定安全性。

因为仅使用python标准库，没有使用复杂的加密算法，信息的加密方式是XOR加密，密钥长度为32位，因此也具有一定危险性，使用时建议绑定到localhost（默认值）以防止受到攻击。加密的实现在[crypt_utils](./captive-portal-auto-login/crypt_utils.py)中。

## 登录机制
每次登录时，先检测是否在线，不在线时执行登录函数，登录函数通过配置好的信息post到网关进行认证，认证完成后检测是否处于联网状态来标识认证是否成功。

检测在线的实现在[detectors](./captive-portal-auto-login/detectors.py)，主要通过请求captive网关并检查返回值的方式进行测试。默认的实现包括三个检测器组用于不同场景。

## urllib hacking
Python标准库的urllib不支持绑定发送地址和网卡，通过自定义opener可以改动其行为，主要在创建socket的函数进行改动即可。在调用login.init()之后，urllib会使用配置文件中指定的地址作为源地址，支持网卡名，ip端口组合和None。

## 合法性声明
本项目仅是一个用于自动化操作的框架，与任何具体的认证系统无关。项目中登录操作的流程与人类通过浏览器手动认证的流程一致。

本项目所涉及的知识、数据、代码和操作流程均来自合法且可公开访问的资源。项目中所执行的操作严格限定为向指定地址发送HTTP请求，不涉及对任何计算机系统、网络或软件的破解、绕过安全措施等行为。

本项目的默认实现仅用于示例和测试用途。所涉及的目标地址均为公开信息，所有操作均遵循合法的标准认证流程，不会对任何认证系统的所有者、版权方及使用者造成任何形式的系统、软硬件损害或侵犯版权。

禁止将本项目用于任何非法用途。 使用者应确保项目的使用不会侵犯他人的合法权益，不损害他人的利益。

本项目对他人使用过程中可能产生的任何影响不承担责任。使用者须自行承担因使用本项目所引发的后果。
