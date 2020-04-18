#!/usr/bin/env python
# -*- coding: utf-8 -*-

from weakref import WeakKeyDictionary
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
    def __init__(self, default, required=False, nullable=False):
        self.required = required
        self.nullable = nullable
        self.default = default
        self.data = WeakKeyDictionary()

    def __get__(self, instance, owner):
        return self.data.get(instance, self.default)

    def __set__(self, instance, value):
        if not self.nullable and not value:
            raise ValueError("Value is not nullable: %s" % value)
        self.data[instance] = value


class CharField(Field):

    def __init__(self, required, nullable, default):
        super().__init__(required=required, nullable=nullable, default=default)

    def __set__(self, instance, value):
        super().__set__(instance, value)
        if not isinstance(value, str) and value:
            raise ValueError("Non string value are not allowed: %s" % value)
        self.data[instance] = value


class ArgumentsField(Field):

    def __init__(self, required, nullable, default):
        super().__init__(required=required, nullable=nullable, default=default)

    def __set__(self, instance, value):
        super().__set__(instance, value)
        if not isinstance(value, dict) and value:
            raise ValueError("Value must be dict: %s" % value)
        self.data[instance] = value


class EmailField(Field):
    def __init__(self, required, nullable, default):
        super().__init__(required=required, nullable=nullable, default=default)

    def __set__(self, instance, value):
        super().__set__(instance, value)
        if value and '@' not in value:
            raise ValueError("Value should contain '@': %s" % value)
        self.data[instance] = value


class PhoneField(Field):

    def __init__(self, required, nullable, default):
        super().__init__(required=required, nullable=nullable, default=default)

    def __set__(self, instance, value):
        super().__set__(instance, value)
        if value and ((not (isinstance(value, str) or isinstance(value, numbers.Number)))
                      or (len(str(value)) != 11) or (str(value)[0] != '7')):
            raise ValueError("Value should starts with 7 and be len of 11: %s" % value)
        self.data[instance] = value


class DateField(Field):

    def __init__(self, required, nullable, default):
        super().__init__(required=required, nullable=nullable, default=default)

    def __set__(self, instance, value):
        super().__set__(instance, value)
        if value:
            try:
                datetime.datetime.strptime(value, '%d.%m.%Y')
            except:
                raise ValueError("Date must be dd.mm.yyyy: %s" % value)
        self.data[instance] = value


class BirthDayField(DateField):

    def __init__(self, required, nullable, default):
        super().__init__(required=required, nullable=nullable, default=default)

    def __set__(self, instance, value):
        super().__set__(instance, value)
        if value and not (datetime.datetime.today().year - datetime.datetime.strptime(value, '%d.%m.%Y').year < 70):
            raise ValueError("Date %s is 70 years ago from now" % value)
        self.data[instance] = value


class GenderField(Field):

    def __init__(self, required, nullable, default):
        super().__init__(required=required, nullable=nullable, default=default)

    def __set__(self, instance, value):
        super().__set__(instance, value)
        if value and not (isinstance(value,  numbers.Number) and value in [0, 1, 2]):
            raise ValueError("Value %s must be number 0, 1 or 2" % value)
        self.data[instance] = value


class ClientIDsField(Field):
    def __init__(self, required):
        super().__init__(required=required, default=None)

    def __set__(self, instance, value):
        super().__set__(instance, value)
        if value and not (isinstance(value, list) and all(isinstance(x, numbers.Number) for x in value)):
            raise ValueError("Value %s must be number 0, 1 or 2" % value)
        self.data[instance] = value


class ClientsInterestsRequest(Field):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True, default=None)

    def __init__(self, client_ids=None, date=None):
        self.client_ids = client_ids
        self.date = date


class OnlineScoreRequest(Field):
    first_name = CharField(required=False, nullable=True, default=None)
    last_name = CharField(required=False, nullable=True, default=None)
    email = EmailField(required=False, nullable=True, default=None)
    phone = PhoneField(required=False, nullable=True, default=None)
    birthday = BirthDayField(required=False, nullable=True, default=None)
    gender = GenderField(required=False, nullable=True, default=None)

    def __init__(self, first_name=None, last_name=None, email=None, phone=None,
                 birthday=None, gender=None):
        self.first_name = first_name
        self.last_name = last_name
        self.email = email
        self.phone = phone
        self.birthday = birthday
        self.gender = gender

        if not ((self.phone and self.email) or (self.first_name and self.last_name)
                or (self.gender is not None and self.birthday)):
            raise ValueError("Phone and mail or first and last name or gender and bday are not exist")


class MethodRequest(Field):
    account = CharField(required=False, nullable=True, default=None)
    login = CharField(required=True, nullable=True, default=None)
    token = CharField(required=True, nullable=True, default=None)
    arguments = ArgumentsField(required=True, nullable=True, default=None)
    method = CharField(required=True, nullable=False, default=None)

    def __init__(self, account, login, token, arguments, method):
        #super().__init__(data_input)
        self.account = account
        self.login = login
        self.token = token
        self.arguments = arguments
        self.method = method

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
    try:
        osr = OnlineScoreRequest(**query)
        if is_admin:
            response = {'score': 42}
        else:
            response = {'score': get_score(store,
                                           phone=osr.phone,
                                           email=osr.email,
                                           birthday=osr.birthday,
                                           gender=osr.gender,
                                           first_name=osr.first_name,
                                           last_name=osr.last_name)}
        code = OK
    except Exception as e:
        code = INVALID_REQUEST
        response = str(e)
    return response, code
    #if osr_is_not_correct:
    #    code = INVALID_REQUEST
    #    response = gen_err_message(all_errs)
    #else:
    #    if not (all(x in query.keys() for x in ['phone', 'email']) or
    #            all(x in query.keys() for x in ['first_name', 'last_name']) or
    #            all(x in query.keys() for x in ['gender', 'birthday'])):
    #        response = "Phone and mail or first and last name or gender and bday are not exist"
    #        code = 422
    #    else:
    #        if is_admin:

    #        else:
    #            osr.set_list_of_atrs(query)
     #           response = {'score': get_score(store, **osr.__dict__)}
     #       code = OK
    #return response, code


def clients_interests_process(query, store, ctx):
    try:
        cir = ClientsInterestsRequest(**query)
        response_dicts = {}
        for i in cir.client_ids:
            response_dicts[i] = get_interests(store, ctx)
            response, code = response_dicts, OK
            ctx['nclients'] = len(query['client_ids'])
    except Exception as e:
        code = INVALID_REQUEST
        response = str(e)


    #cir = ClientsInterestsRequest()
    #cir_is_not_correct, all_errs = cir.is_correct(query)
    #if cir_is_not_correct:
    #    code = INVALID_REQUEST
    #    response = gen_err_message(all_errs)
    #else:
    #    response_dicts = {}
    #    for i in query['client_ids']:
    #        response_dicts[i] = get_interests(store, ctx)
    #    response, code = response_dicts, OK
    #    ctx['nclients'] = len(query['client_ids'])

    return response, code


def method_handler(request, ctx, store):
    logging.info("method_handler starts")
    request_body = request["body"]
    try:
        mr = MethodRequest(**request_body)
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
    except Exception as e:
        response, code = ERRORS[INVALID_REQUEST], INVALID_REQUEST

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
                    logging.exception("Unexpected error: %s" % str(e))
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