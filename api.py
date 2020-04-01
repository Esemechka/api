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
                ((not email) or (email and ('@' in email))):
            return 1
        else:
            return 0


class PhoneField(Field):
    def is_correct(self, phone_number):
        if (isinstance(phone_number, str) or isinstance(phone_number, numbers.Number)) \
                and ((not phone_number) or (len(str(phone_number)) == 11 and str(phone_number)[0] == '7')):
            return 1
        else:
            return 0


class DateField(Field):
    def is_correct(self, date_value):
        if not str(date_value):
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
        if not sex:
            return 1
        else:
            if isinstance(sex,  numbers.Number) and sex in [0, 1, 2]:
                return 1
            else:
                return 0


class ClientIDsField(Field):
    def __init__(self, required):
        self.required = required

    def is_correct(self, clients):
        if isinstance(clients, list) and clients != [] and len([x for x in clients if isinstance(x, numbers.Number)]) == len(clients):
            return 1
        else:
            return 0


class ListOfFields():
    def is_correct_attrs(self, data):
        cls = self.__class__
        dict_of_correct_id = {}
        for k, v in cls.__dict__.items():
            if isinstance(v, Field):
                if k in data:
                    if v.is_correct(data[k]):
                        dict_of_correct_id[k] = 1
                    else:
                        dict_of_correct_id[k] = 0

                else:
                    if v.required:
                        dict_of_correct_id[k] = 0
                    else:
                        dict_of_correct_id[k] = 1
        return dict_of_correct_id

    def set_list_of_atrs(self, data):
        cls = self.__class__
        for k, v in cls.__dict__.items():
            if isinstance(v, Field):
                if k in data:
                    setattr(self, k, data[k])
                else:
                    setattr(self, k, None)


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
        msg = (request.account + request.login + SALT).encode('utf-8')
        digest = hashlib.sha512(msg).hexdigest()
        #logging.info(f'msg is {msg}')
        #logging.info(f'digest is {digest}, \n token is {request.token}')
    if digest == request.token:
        return True
    else:
        return False


def online_score_process(query, store, is_admin):
    osr = OnlineScoreRequest()
    osr_dict_of_correct_id = osr.is_correct_attrs(query)
    if 0 in osr_dict_of_correct_id.values():
        not_correct = [k for k, v in osr_dict_of_correct_id.items() if v == 0]
        code = INVALID_REQUEST
        response = f'fields {not_correct} are not correct'
    else:
        if not (all(x in query.keys() for x in ['phone', 'email']) or
                all(x in query.keys() for x in ['first_name', 'last_name']) or
                all(x in query.keys() for x in ['gender', 'birthday'])):
            response = "Phone and mail or first and last name or gender and bday are null"
            code = 422
        else:
            func_args = {}
            for k, v in osr_dict_of_correct_id.items():
                if k in query.keys():
                    func_args[k] = v
                else:
                    func_args[k] = None
            if is_admin:
                response = {'score': 42}
            else:
                response = {'score': get_score(store, **func_args)}
            code = OK
    return response, code


def clients_interests_process(query, store, ctx):
    cir = ClientsInterestsRequest()
    cir_dict_of_correct_id = cir.is_correct_attrs(query)
    if 0 in cir_dict_of_correct_id.values():
        not_correct = [k for k, v in cir_dict_of_correct_id.items() if v == 0]
        code = INVALID_REQUEST
        response = f'fields {not_correct} are not correct'
    else:
        response_dicts = {}
        for i in query['client_ids']:
            response_dicts[i] = get_interests(store, ctx)
        response, code = response_dicts, OK
        ctx['nclients'] = len(query['client_ids'])

    return response, code


def method_handler(request, ctx, store):
    logging.info("method_handler starts")
    request_body = request["body"]
    mr = MethodRequest()

    dict_of_correct_id = mr.is_correct_attrs(request_body)
    if 0 in dict_of_correct_id.values():
        response, code = ERRORS[INVALID_REQUEST], INVALID_REQUEST
    else:
        mr.set_list_of_atrs(request_body)
        ok_auth = check_auth(mr)
        if not ok_auth:
            response, code = ERRORS[FORBIDDEN], FORBIDDEN
        else:
            query = mr.__getattribute__('arguments')
            if mr.method == "online_score":
                response, code = online_score_process(query, store, mr.is_admin)
                ctx['has'] = {k: v for k, v in query.items()}

            if mr.method == 'clients_interests':
                response, code = clients_interests_process(query, store, ctx)

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
            path = self.path.strip("/")
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