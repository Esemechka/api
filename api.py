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


class ListOfFields():
    def is_correct_attrs(self, data):
        cls = self.__class__
        atrs_correctness = {}
        for k, v in cls.__dict__.items():
            if not isinstance(v, Field):
                continue

            if k in data:
                data_k = data[k]
                if not data_k:
                    if v.nullable:
                        atrs_correctness[k] = True, '1'
                    else:
                        atrs_correctness[k] = False, f'{k} is not nullable'
                else:
                    full_msg = f'Error in field {k}: ' + v.is_correct(data_k)[1]
                    atrs_correctness[k] = v.is_correct(data_k)[0], full_msg
            else:
                if v.required:
                    atrs_correctness[k] = False, f'{k} is required'
                else:
                    atrs_correctness[k] = True, '1'

        return atrs_correctness

    def is_correct(self, data):
        #cls = self.__class__
        attrs_correctness = self.is_correct_attrs(data)
        all_errs = []
        for attr, correctness in attrs_correctness.items():
            is_correct, errs = correctness
            if not is_correct:
                all_errs.append(errs)

        return len(all_errs), all_errs

    def set_list_of_atrs(self, data):
        cls = self.__class__
        for k, v in cls.__dict__.items():
            if isinstance(v, Field):
                if k in data:
                    setattr(self, k, data[k])
                else:
                    setattr(self, k, None)


class CharField(Field):
    def is_correct(self, input_data):
        if isinstance(input_data, str):
            return True, ''
        else:
            return False, 'field must bе string'


class ArgumentsField(Field):
    def is_correct(self, input_data):
        if isinstance(input_data, dict):
            return True, ''
        else:
            return False, 'field must bе list'


class EmailField(CharField):
    def is_correct(self, email):
        if super().is_correct(email) and ('@' in email):
            return True, ''
        else:
            return False, 'email should contain "@"'


class PhoneField(Field):
    def is_correct(self, phone_number):
        if (isinstance(phone_number, str) or isinstance(phone_number, numbers.Number)) \
                and (len(str(phone_number)) == 11 and str(phone_number)[0] == '7'):
            return True, ''
        else:
            return False, 'phone number should starts with 7 and contain 11 characters'


class DateField(Field):
    def is_correct(self, date_value):
        try:
            datetime.datetime.strptime(date_value, '%d.%m.%Y')
            return True, ''
        except:
            return False, 'date format should be "dd.mm.yyyy"'


class BirthDayField(DateField):
    def is_correct(self, date_value):
        if (super().is_correct(date_value)[0]
                and
                datetime.datetime.today().year - datetime.datetime.strptime(date_value, '%d.%m.%Y').year < 70):
            return True, ''
        else:
            return False, super().is_correct(date_value)[1]+' and be less then 70 years ago'


class GenderField(Field):
    def is_correct(self, sex):
        if isinstance(sex,  numbers.Number) and sex in [0, 1, 2]:
            return True, ''
        else:
            return False, 'sex may be only 0, 1 or 2'


class ClientIDsField(Field):
    def __init__(self, required):
        super().__init__(required=required)

    def is_correct(self, clients):
        if isinstance(clients, list) and all(isinstance(x, numbers.Number) for x in clients):
            return True, ''
        else:
            return False, 'ids should be list of numbers'


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
        logging.info(f'msg is {msg}')
        logging.info(f'digest is {digest}, \n token is {request.token}')
    if digest == request.token:
        return True
    else:
        return False


def gen_err_message(all_errs):
    if len(all_errs) == 1:
        return all_errs[0]
    else:
        whole_msg = ''
        for err in all_errs[:-1]:
            whole_msg = whole_msg+err+'; '
        return whole_msg+all_errs[-1]


def online_score_process(query, store, is_admin):
    osr = OnlineScoreRequest()
    osr_is_not_correct, all_errs = osr.is_correct(query)
    if osr_is_not_correct:
        code = INVALID_REQUEST
        response = gen_err_message(all_errs)
    else:
        if not (all(x in query.keys() for x in ['phone', 'email']) or
                all(x in query.keys() for x in ['first_name', 'last_name']) or
                all(x in query.keys() for x in ['gender', 'birthday'])):
            response = "Phone and mail or first and last name or gender and bday are not exist"
            code = 422
        else:
            if is_admin:
                response = {'score': 42}
            else:
                osr.set_list_of_atrs(query)
                response = {'score': get_score(store, **osr.__dict__)}
            code = OK
    return response, code


def clients_interests_process(query, store, ctx):
    cir = ClientsInterestsRequest()
    cir_is_not_correct, all_errs = cir.is_correct(query)
    if cir_is_not_correct:
        code = INVALID_REQUEST
        response = gen_err_message(all_errs)
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
    mr_is_not_correct, all_errs = mr.is_correct(request_body)
    if mr_is_not_correct:
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