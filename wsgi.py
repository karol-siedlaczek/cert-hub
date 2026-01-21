from cert_registry.app import create_app
from cert_registry.config import Config

app = create_app(Config.load_from_env())
