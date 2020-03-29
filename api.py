#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import numbers
import json
import datetime
import logging
import hashlib
import uuid
from optparse import OptionParser
from http.server import HTTPServer, BaseHTTPRequestHandler
from scoring import get_score, get_interests

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}

config = {
    "LOG_DIR": None
}


class Field(object):
    def __init__(self, required=False, nullable=False):
        self.required = required
        self.nullable = nullable


class CharField(Field):
    def is_correct(self, input_data):
        return isinstance(input_data, str)


class ArgumentsField(Field):
    def is_correct(self, input_data):
        return isinstance(input_data, dict)


class EmailField(CharField):
    def is_correct(self, email):
        if super().is_correct(email) and \
                ((not bool(email)) or (bool(email) and ('@' in email))):
            return 1
        else:
            return 0


class PhoneField(Field):
    def is_correct(self, phone_number):
        if (isinstance(phone_number, str) or isinstance(phone_number, numbers.Number)) \
                and ((not bool(str(phone_number))) or (len(str(phone_number)) == 11 and str(phone_number)[0] == '7')):
            return 1
        else:
            return 0


class DateField(Field):
    def is_correct(self, date_value):
        if not bool(str(date_value)):
            return 1
        else:
            try:
                datetime.datetime.strptime(date_value, '%d.%m.%Y')
                return 1
            except:
                return 0


class BirthDayField(Field):
    def is_correct(self, date_value):
        if not bool(str(date_value)):
            return 1
        else:
            try:
                date_norm = datetime.datetime.strptime(date_value, '%d.%m.%Y')
                return datetime.datetime.today().year - date_norm.year < 70
            except:
                return 0


class GenderField(Field):
    def is_correct(self, sex):
        if not bool(str(sex)):
            return 1
        else:
            if isinstance(sex,  numbers.Number) and sex in [0, 1, 2]:
                return 1
            else:
                return 0


class ClientIDsField(object):
    def __init__(self, required):
        self.required = required

    def is_correct(self, clients):
        if isinstance(clients, list) and clients != [] and len([x for x in clients if isinstance(x, numbers.Number)]) == len(clients):
            return 1
        else:
            return 0


class ListOfFields(Field):
    def is_correct_attrs(self, data):
        cls = self.__class__
        list_of_incorrects = []
        list_of_corrects_not_null = []
        args_to_set = {}
        not_correct = 0
        for k, v in cls.__dict__.items():
            if k.startswith("__") or callable(v) or isinstance(v, property):
                continue
            elif k in data:
                if v.is_correct(data[k]):
                    setattr(self, k, data[k])
                    args_to_set[k] = data[k]
                    if bool(k):
                        list_of_corrects_not_null.append(k)
                else:
                    list_of_incorrects.append(k)
            else:
                args_to_set[k] = None
                setattr(self, k, None)
                if not v.required:
                    continue
                else:
                    not_correct = 1
        return not_correct, list_of_incorrects, list_of_corrects_not_null, args_to_set


class ClientsInterestsRequest(ListOfFields):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)


class OnlineScoreRequest(ListOfFields):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)


class MethodRequest(ListOfFields):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512((datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).encode('utf-8')).hexdigest()
    else:
        digest = hashlib.sha512((str(request.account) + str(request.login) + str(SALT)).encode('utf-8')).hexdigest()
        print(digest)
    if digest == request.token:
        return True
    return False


def method_handler(request, ctx, store):
    logging.info("method_handler starts")
    request_body = request["body"]
    mr = MethodRequest()
    not_correct, list_of_incorrects, list_of_corrects_not_null, args_to_set = mr.is_correct_attrs(request_body)
    logging.info(f"request is not correct {not_correct};"
                 f" list of incorrect fields {list_of_incorrects}; "
                 f"list of correct fields not null {list_of_corrects_not_null}")

    if not_correct == 1:
        response, code = ERRORS[INVALID_REQUEST], INVALID_REQUEST
        return response, code
    else:
        ok_auth = check_auth(mr)
        if not ok_auth:
            return ERRORS[FORBIDDEN], FORBIDDEN
        else:
            query = mr.arguments
            if mr.method == "online_score":
                osr = OnlineScoreRequest()
                osr_correct, osr_list_of_incorrects, osr_list_of_not_null, osr_args_to_set = osr.is_correct_attrs(query)
                ctx['has'] = osr_list_of_not_null
                print(osr.__dict__)

                if osr_correct == 0:
                    if len(osr_list_of_incorrects) > 0:
                        response, code = osr_list_of_incorrects, INVALID_REQUEST
                        return response, code
                elif not (
                        ('phone' in osr_list_of_not_null and 'email' in osr_list_of_not_null) or
                        ('first_name' in osr_list_of_not_null and 'last_name' in osr_list_of_not_null) or
                        ('gender' in osr_list_of_not_null and 'birthday' in osr_list_of_not_null)
                ):
                    response = "Phone and email or first and last name or gender and birtday are null"
                    code = 422
                    return response, code
                elif mr.is_admin:
                    return 42, 200
                else:
                    response, code = {'score': get_score(store, **osr_args_to_set)}, 200
                    return response, code

            if mr.method == 'clients_interests':
                cir = ClientsInterestsRequest()
                cir_correct, cir_list_of_incorrects, cir_list_of_corrects_not_null, cir_args_to_set = cir.is_correct_attrs(query)
                if (cir_correct == 0) and len(cir_list_of_incorrects) > 0:
                    response, code = cir_list_of_incorrects, INVALID_REQUEST
                    return response, code
                else:
                    response_dicts = {}
                    ctx['nclients'] = len(cir.client_ids)
                    for i in cir.client_ids:
                        response_dicts[i] = get_interests(store, ctx)
                    response, code = response_dicts, OK
                    return response, code


class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length'])).decode()
            request = json.loads(data_string)#.decode("ascii"))
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/") #request path
            print('path', path)
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request,
                                                       "headers": self.headers},
                                                       context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r).encode())
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    try:
        server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
        logging.info("Starting server at %s" % opts.port)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        server.server_close()
    except Exception as e:
        exception_message = "Server error"
        logging.exception(exception_message)
        logging.error(e)