[![GitHub release](https://img.shields.io/github/release/Da4ndo/USB.ENC)](https://gitHub.com/Da4ndo/USB.ENC/releases/)
[![GitHub license](https://img.shields.io/github/license/Da4ndo/USB.ENC)](https://github.com/Da4ndo/USB.ENC/blob/master/LICENSE)
[![GitHub issues](https://img.shields.io/github/issues/Da4ndo/USB.ENC)](https://GitHub.com/Da4ndo/USB.ENC/issues/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)
[![Open Source? Yes!](https://badgen.net/badge/Open%20Source%20%3F/Yes%21/blue?icon=github)](https://github.com/Da4ndo/USB.ENC)

# USB.ENC

**USB.ENC** is an ***open-source*** crypter algorithm that use *RSA encryption*. 

## How does it work?

 - **USB.ENC** loads the *private key* from an USB which needs to be called `ENC_PRIVATE`.
 - You can also add a **password** to the *saved private key* so it is **very safe** because it and you keep it separated in an USB.
 
> You can share your *public key* so anybody can **encrypt** files with it, but only you can **decrypt** it.
> Then they send their *public key* and you **encrypt** files then you send the encrypted files back to them.

![](https://github.com/Da4ndo/USB.ENC/images/encrypt.usb.enc.png)
> How to encrypt file example 👆

![](https://github.com/Da4ndo/USB.ENC/images/encrypted_data.usb.enc.png)
> How encrypted data zip looks like example 👆

## CHANGELOG

1.0.0 (12/25/2021):

- First Release

0.3.0 - 1.0.0 (xx/xx/xx):

- Testing
- Few changes
- Directory issue solving

0.1.0 - 0.3.0 (12/24/2021):

- developing

## Usage

> usage: usb.enc.exe [-h] [-g GENERATE_KEYS [GENERATE_KEYS ...]] [-e ENCRYPT [ENCRYPT ...]] [-d DECRYPT [DECRYPT ...]] [-p PUBLIC_KEY [PUBLIC_KEY ...]]
> 
> options:
> 
>   - -h, --help            show this help message and exit
>   
>   - -g GENERATE_KEYS [GENERATE_KEYS ...], --generate-keys GENERATE_KEYS [GENERATE_KEYS ...]
>                         Save private key to a USB and public key somwhere you specify. eg.: -g
>                         "C:\asd\" "YOUR_PASSWORD(optional)"
>                         
>   - -e ENCRYPT [ENCRYPT ...], --encrypt ENCRYPT [ENCRYPT ...]
>                         Encrypt file. eg.: "FileLoc" "PubKeyDirectoryLoc"
>                         
>   - -d DECRYPT [DECRYPT ...], --decrypt DECRYPT [DECRYPT ...]
>                         Decrypt file. eg.: "FileLoc" "YOUR_PASSWORD(optional)"
>                         
>   - -p PUBLIC_KEY [PUBLIC_KEY ...], --public-key PUBLIC_KEY [PUBLIC_KEY ...]
>                         Get public key, if you lost it. eg.: -p "PubKeyDirectoryLoc" "YOUR_PASSWORD(optional)"