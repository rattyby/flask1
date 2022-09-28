from flask import Flask, jsonify, request
from flask.views import MethodView
from sqlalchemy import Column, Integer, String, DateTime, func, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm.session import sessionmaker
from sqlalchemy.exc import IntegrityError
import atexit
import pydantic
from typing import Optional
from flask_bcrypt import Bcrypt

app = Flask('server')
bcrypt = Bcrypt(app)

DSN = 'postgresql://app:1234@127.0.0.1:5431/advert'
engine = create_engine(DSN)
Session = sessionmaker(bind=engine)
Base = declarative_base()


class HttpError(Exception):

    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        self.message = message


@app.errorhandler(HttpError)
def http_error_handler(err: HttpError):
    response = jsonify({
        'status': 'error',
        'message': err.message
    })
    response.status_code = err.status_code
    return response


def on_exit():
    engine.dispose()


atexit.register(on_exit)


class CreateUserSchema(pydantic.BaseModel):
    username: str
    password: str

    @pydantic.validator('password')
    def strong_password(cls, value: str):
        if len(value) < 8:
            raise ValueError('Password is too short')
        return bcrypt.generate_password_hash(value.encode()).decode()


class PatchUserSchema(CreateUserSchema):
    username: Optional[str]
    password: Optional[str]


def validate(Schema, data: dict):
    try:
        data_validated = Schema(**data).dict(exclude_none=True)
    except pydantic.ValidationError as er:
        raise HttpError(400, er.errors())
    return data_validated


class User(Base):
    __tablename__ = 'user'
    id = Column(Integer, primary_key=True)
    username = Column(String(40), unique=True, nullable=False)
    password = Column(String, nullable=False)
    created = Column(DateTime, server_default=func.now())


def get_user(id_user: int, session: Session) -> User:
    user = session.query(User).get(id_user)
    if user is None:
        raise HttpError(404, 'User not found')
    return user


class CreateAdSchema(pydantic.BaseModel):
    head: str
    body: Optional[str]
    owner: int

    @pydantic.validator('owner')
    def user_exists(cls, value: int):
        get_user(value, Session())
        return value

    @pydantic.validator('head')
    def meaningful_head(cls, value: str):
        if len(value) < 2:
            raise ValueError('Head of ad is too short')
        return value


class PatchAdSchema(CreateAdSchema):
    head: Optional[str]
    # body: Optional[str]
    # owner: int
    # password: str
    #
    # @pydantic.validator('owner', 'password')
    # def user_exists(cls, values: tuple):
    #     user = get_user(values[0], Session())
    #     if not bcrypt.check_password_hash(user.password, values[1]):
    #         raise HttpError(403, 'Incorrect password')
    #     return values


class Ad(Base):
    __tablename__ = 'advert'

    id = Column(Integer, primary_key=True)
    head = Column(String(40), nullable=False)
    body = Column(String)
    created = Column(DateTime, server_default=func.now())
    owner = Column(String, nullable=False)


def get_ad(id_ad: int, session: Session) -> Ad:
    ad = session.query(Ad).get(id_ad)
    if ad is None:
        raise HttpError(404, 'Ad not found')
    return ad


Base.metadata.create_all(engine)


class UserView(MethodView):

    def get(self, id_user):
        with Session() as session:
            user = get_user(id_user=id_user, session=session)
            return jsonify({'username': user.username, 'date': user.created.isoformat()})

    def post(self):
        json_data_validated = validate(CreateUserSchema, request.json)
        with Session() as session:
            new_user = User(**json_data_validated)
            try:
                session.add(new_user)
                session.commit()
            except IntegrityError as er:
                raise HttpError(400, 'User already exists')
            return jsonify({'status': 'ok', 'id': new_user.id})

    def patch(self, id_user):
        json_data_validated = validate(PatchUserSchema, request.json)
        with Session() as session:
            user = get_user(id_user, session)
            for key, value in json_data_validated.items():
                setattr(user, key, value)
            try:
                session.add(user)
                session.commit()
            except IntegrityError:
                raise HttpError(400, 'Such username already exists')
        return jsonify({'status': 'success'})

    def delete(self, id_user):
        with Session() as session:
            user = get_user(id_user, session)
            session.delete(user)
            session.commit()
        return jsonify({'status': 'success'})


class AdView(MethodView):

    def get(self, id_ad):
        with Session() as session:
            ad = get_ad(id_ad, session)
            return jsonify({'head': ad.head, 'text': ad.body, 'owner': ad.owner, 'date': ad.created.isoformat()})

    def post(self):
        json_data_validated = validate(CreateAdSchema, request.json)
        with Session() as session:
            new_ad = Ad(**json_data_validated)
            session.add(new_ad)
            session.commit()
            return jsonify({'status': 'ok', 'id': new_ad.id})

    def patch(self, id_ad):
        json_data_validated = validate(PatchAdSchema, request.json)
        with Session() as session:
            ad = get_ad(id_ad, session)
            if ad.owner != str(json_data_validated['owner']):
                raise HttpError(400, 'Ad has another owner')
            for key, value in json_data_validated.items():
                setattr(ad, key, value)
            session.add(ad)
            session.commit()
        return jsonify({'status': 'success'})

    def delete(self, id_ad):
        with Session() as session:
            ad = get_ad(id_ad, session)
            session.delete(ad)
            session.commit()
        return jsonify({'status': 'success'})


app.add_url_rule('/users/', view_func=UserView.as_view('create_user'), methods=['POST'])
app.add_url_rule('/users/<int:id_user>', view_func=UserView.as_view('get_user'), methods=['GET', 'PATCH', 'DELETE'])

app.add_url_rule('/ads/', view_func=AdView.as_view('create_ad'), methods=['POST'])
app.add_url_rule('/ads/<int:id_ad>', view_func=AdView.as_view('view_ads'), methods=['GET', 'PATCH', 'DELETE'])
app.run()
