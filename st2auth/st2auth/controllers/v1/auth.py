# Copyright 2020 The StackStorm Authors.
# Copyright 2019 Extreme Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from six.moves import http_client
from oslo_config import cfg

from st2common.exceptions.auth import TokenNotFoundError, TokenExpiredError
from st2common.exceptions.param import ParamException
from st2common.router import exc
from st2common.router import Response
from st2common.util import auth as auth_utils
from st2common.util import api as api_utils
from st2common import log as logging
import st2auth.handlers as handlers
from st2common import router
from six.moves import urllib
import datetime
import json
import base64
import random
from xml.dom.expatbuilder import parseString
from st2common.models.db.auth import UserDB, TokenDB
from st2common.persistence.rbac import UserRoleAssignment
from st2common.models.db.rbac import UserRoleAssignmentDB
from st2common.util import date as date_utils

HANDLER_MAPPINGS = {
    "proxy": handlers.ProxyAuthHandler,
    "standalone": handlers.StandaloneAuthHandler,
}

LOG = logging.getLogger(__name__)


# 创建用户
def _create_user(username, password, email, firstname, lastname, displayname):
    user_db = UserDB(name=username, password=password, email=email, firstname=firstname, lastname=lastname,
                     displayname=displayname)
    user_db.save()


class TokenValidationController(object):
    def post(self, request):
        token = getattr(request, "token", None)

        if not token:
            raise exc.HTTPBadRequest("Token is not provided.")

        try:
            return {"valid": auth_utils.validate_token(token) is not None}
        except (TokenNotFoundError, TokenExpiredError):
            return {"valid": False}
        except Exception:
            msg = "Unexpected error occurred while verifying token."
            LOG.exception(msg)
            raise exc.HTTPInternalServerError(msg)


class TokenController(object):
    validate = TokenValidationController()

    def __init__(self):
        try:
            self.handler = HANDLER_MAPPINGS[cfg.CONF.auth.mode]()
            self.st2_auth_handler = handlers.ProxyAuthHandler()
        except KeyError:
            raise ParamException("%s is not a valid auth mode" % cfg.CONF.auth.mode)

    def post(self, request, **kwargs):

        headers = {}
        if "x-forwarded-for" in kwargs:
            headers["x-forwarded-for"] = kwargs.pop("x-forwarded-for")

        authorization = kwargs.pop("authorization", None)

        samlresponse = kwargs.pop("samlresponse", None)

        if samlresponse:
            userinfo = parse_saml_response(samlresponse)
            username = userinfo['itcode']
            # 判断用户是否存在 用户不存在创建用户
            user_info = UserDB.objects(name=username)

            adfs_url = cfg.CONF.rbac.adfs
            if len(user_info) == 0:
                password = ''.join(
                    random.sample('1235689abcdefghijklmnopqrstuvwxyz!@#$%^&*()',
                                  10))
                _create_user(username=username, password=password, email=userinfo['email'],
                             firstname=userinfo['firstname'], lastname=userinfo['lastname'],
                             displayname=userinfo['displayname'])

                role = cfg.CONF.rbac.role
                role_assignment_db = UserRoleAssignmentDB(
                    user=username,
                    role=role,
                    source='',
                    description='',
                    is_remote=False,
                )
                UserRoleAssignment.add_or_update(role_assignment_db)
                st2_auth_token_create_request = {
                    "user": username,
                    "ttl": None,
                }
                adfs_url = cfg.CONF.rbac.adfs
                token = self.st2_auth_handler.handle_auth(
                    request=st2_auth_token_create_request,
                    remote_addr=adfs_url,
                    remote_user=username,
                    headers={},
                )

                return process_successful_authn_response(referer=adfs_url, token=token,role=role)
            token_ = TokenDB.objects(user=username).order_by('-expiry').first()
            role_ = UserRoleAssignmentDB.objects(user=username).first()
            role = role_.role
            if token_:

                if token_.expiry <= date_utils.get_datetime_utc_now():
                    st2_auth_token_create_request = {
                        "user": username,
                        "ttl": None,
                    }
                    token = self.st2_auth_handler.handle_auth(
                        request=st2_auth_token_create_request,
                        remote_addr=adfs_url,
                        remote_user=username,
                        headers={},
                    )

                    return process_successful_authn_response2(referer=adfs_url, token=token,role=role)

                return process_successful_authn_response(referer=adfs_url, token=token_,role=role)

        if authorization:
            authorization = tuple(authorization.split(" "))
        token = self.handler.handle_auth(
            request=request,
            headers=headers,
            remote_addr=kwargs.pop("remote_addr", None),
            remote_user=kwargs.pop("remote_user", None),
            authorization=authorization,
            **kwargs,
        )
        return process_successful_response(token=token)


CALLBACK_SUCCESS_RESPONSE_BODY = """
<html>
    <script>
        var replace_url = "%s?token=%s";
        window.location.replace(replace_url);
    </script>
</html>
"""


def process_successful_authn_response2(referer, token,role):
    token_json = {
        "id": str(token.id),
        "user": token.user,
        "token": token.token,
        "expiry": str(token.expiry),
        "service": False,
        "metadata": {},
        "role":role
    }
    CALLBACK_SUCCESS_RESPONSE_BODY2 = """
    <html>
        <script>
            var replace_url = "%s?token=%s";
            window.location.replace(replace_url);
        </script>
    </html>
    """
    from urllib.parse import quote
    body = CALLBACK_SUCCESS_RESPONSE_BODY2 % (referer,quote(str(json.dumps(token_json))))
    resp = router.Response(body=body)
    resp.headers["Content-Type"] = "text/html"
    resp.set_cookie(
        "st2-auth-token",
        value=urllib.parse.quote(json.dumps(token_json)),
        expires=datetime.timedelta(seconds=60),
        overwrite=True,
    )

    return resp


def process_successful_authn_response(referer, token,role):
    token_json = {
        "id": str(token.id),
        "user": token.user,
        "token": token.token,
        "expiry": str(token.expiry),
        "service": False,
        "metadata": {},
        "role":role
    }
    from urllib.parse import quote
    body = CALLBACK_SUCCESS_RESPONSE_BODY % (referer,quote(str(json.dumps(token_json))))
    resp = router.Response(body=body)
    resp.headers["Content-Type"] = "text/html"
    resp.set_cookie(
        "st2-auth-token",
        value=urllib.parse.quote(json.dumps(token_json)),
        expires=datetime.timedelta(seconds=60),
        overwrite=True,
    )

    return resp


def process_successful_response(token):
    resp = Response(json=token, status=http_client.CREATED)
    # NOTE: gunicon fails and throws an error if header value is not a string (e.g. if it's None)
    resp.headers["X-API-URL"] = api_utils.get_base_public_api_url()
    return resp


# 获取用户基本信息
def parse_saml_response(xml_str):
    try:
        str_url = base64.b64decode(xml_str).decode("utf-8")
        # 字符串转换成xml.dom.minidom.Document对象 xml_data是xml格式字符串
        DOMTree = parseString(str_url)
        collection = DOMTree.documentElement
        # 集合你要的标签
        VariationChilds = collection.getElementsByTagName("AttributeStatement")
        # 获取token 有效时间
        time_tag = collection.getElementsByTagName("Conditions")
        start_time = time_tag[0].attributes['NotBefore'].value
        end_time = time_tag[0].attributes['NotOnOrAfter'].value

        # 获取状态
        status_tag = collection.getElementsByTagName("samlp:StatusCode")
        status = status_tag[0].attributes['Value'].value.split(':')[-1]

        # 进行遍历取值
        for VariationChild in VariationChilds:
            itcode = \
                VariationChild.getElementsByTagName('AttributeValue')[
                    0].childNodes[
                    0].data
            email = \
                VariationChild.getElementsByTagName('AttributeValue')[
                    1].childNodes[
                    0].data
            firstname = \
                VariationChild.getElementsByTagName('AttributeValue')[
                    2].childNodes[
                    0].data
            lastname = \
                VariationChild.getElementsByTagName('AttributeValue')[
                    3].childNodes[
                    0].data
            displayname = \
                VariationChild.getElementsByTagName('AttributeValue')[
                    4].childNodes[
                    0].data
            data = {"itcode": itcode, "email": email, "firstname": firstname,
                    "lastname": lastname, "displayname": displayname,
                    "start_time": start_time,
                    "end_time": end_time,
                    "status": status}
            return data
    except:
        print("解析异常")


token_controller = TokenController()
token_validation_controller = TokenValidationController()
