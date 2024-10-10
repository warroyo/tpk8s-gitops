#!/usr/bin/env python

import os
import logging
import requests
from apscheduler.schedulers.blocking import BlockingScheduler
from kubernetes import client, config,utils
from kubernetes.client.rest import ApiException
import time
import base64


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def getAccessToken(csp_host,csp_token):
    try:
        response = requests.post('https://%s/csp/gateway/am/api/auth/api-tokens/authorize?refresh_token=%s' % (csp_host,csp_token))
        response.raise_for_status()
    except Exception as e:
        logging.error(e)
        return None
    else:
        access_token = response.json()['access_token']
        expires_in = response.json()['expires_in']
        expire_time = time.time() + expires_in
        return access_token, expire_time


class Controller():

    csp_token = None
    access_token = None
    access_token_expiration = None
    csp_token = os.environ['CSP_TOKEN']
    csp_host = "console.tanzu.broadcom.com"
    update_needed = False


    try:
        logging.info("getting initial token")
        access_token, access_token_expiration = getAccessToken(csp_host,csp_token)
        if access_token is None:
            raise Exception("Request for access token failed.")
    except Exception as e:
        logging.error(e)
    else:
        logging.info("access token recieved")


    @classmethod    
    def update_token(cls,access_token, expire_time):
        cls.access_token =access_token
        cls.access_token_expiration = expire_time
        cls.update_needed = True

     #decorator function for rereshing token
    def refreshToken(decorated):
        def wrapper(api,*args,**kwargs):
            if time.time() > api.access_token_expiration:
                logging.info("token expired regenerating")
                api.access_token, api.access_token_expiration =  getAccessToken(api.csp_host,api.csp_token)
                Controller.update_token(api.access_token,api.access_token_expiration)
            return decorated(api,*args,**kwargs)

        return wrapper

    @refreshToken
    def run(self):
        logging.info("creating k8s secret")
        config.load_incluster_config()
        # config.load_kube_config()
        b = base64.b64encode(bytes(self.access_token, 'utf-8')) # bytes
        base64_str = b.decode('utf-8') # convert bytes to string
        k8s_client = client.ApiClient()
        secret = {'apiVersion': 'v1', 'kind': 'Secret', 'metadata': {'name': 'ucp-access-token',"namespace": "ucp-token-generator"}, 'data' : {"access_token": base64_str}}
        try: 
            utils.create_from_dict(k8s_client, secret)
        except utils.FailToCreateError as e:
            if e.api_exceptions[0].status == 409 and self.update_needed:
                logging.info("secret exists,updating secret")
                try:
                    v1 = client.CoreV1Api()
                    patch = {'data' : {"access_token": base64_str}}
                    v1.patch_namespaced_secret(name='ucp-access-token',namespace='ucp-token-generator',body=patch)
                except Exception as e:
                    logging.error("error updating secret")
                    raise
            elif e.api_exceptions[0].status == 409:
                logging.info("secret exists but no update needed")
            else:
                raise
                



controller = Controller()

gslb_sched = BlockingScheduler()
gslb_sched.add_job(id='run gslb job',func=controller.run,trigger='interval',seconds=5)
gslb_sched.start()