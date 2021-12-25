[![GitHub release](https://img.shields.io/github/release/Mesteri05/USB.ENC)](https://GitHub.com/Mesteri05/USB.ENC/releases/)
[![GitHub license](https://img.shields.io/github/license/Mesteri05/USB.ENC)](https://github.com/Mesteri05/USB.ENC/blob/master/LICENSE)
[![GitHub issues](https://img.shields.io/github/issues/Mesteri05/USB.ENC)](https://GitHub.com/Mesteri05/USB.ENC/issues/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square)](http://makeapullrequest.com)
[![Open Source? Yes!](https://badgen.net/badge/Open%20Source%20%3F/Yes%21/blue?icon=github)](https://github.com/Mesteri05/USB.ENC)

# USB.ENC

USB.ENC is an **open-source** crypter algorithm that use RSA encryption. It loads the private key from an USB which needs to be called "ENC_PRIVATE".
You can share the public key and anybofy can encrypt files, but only you can decrypt it.
And they can send their public key and you can encrypt files then send it to them.
You can also add a password to the saved private key so it is very safe beacese it and you keep it separated in an USB.

## CHANGELOG

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
>                         Get public key, if you lost it. eg.: -p "PubKeyDirectoryLoc"
>                         "YOUR_PASSWORD(optional)"
