from app import create_app, mongo
from flask_sslify import SSLify

app = create_app()
sslify = SSLify(app)

if __name__ == "__main__":
    app.run(ssl_context=('server.crt', 'server.key'), debug=True)

