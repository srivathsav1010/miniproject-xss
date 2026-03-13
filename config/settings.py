class Config:
    DEBUG  = True
    PORT   = 5000
    HOST   = '0.0.0.0'
    SECRET = 'change-this-in-production'

class ProductionConfig(Config):
    DEBUG = False
    PORT  = 80
