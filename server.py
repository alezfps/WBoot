#!/usr/bin/env python3

import os
import json
import time
import hashlib
import mimetypes
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path

from flask import Flask, request, jsonify, send_file, abort
from werkzeug.utils import secure_filename
import redis
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Configuration
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'change-this-secret-key')
    AUTH_TOKEN = os.environ.get('AUTH_TOKEN', 'your-secure-auth-token-here')
    PLUGIN_DIR = os.environ.get('PLUGIN_DIR', '/var/www/plugins')
    MAX_DOWNLOAD_SIZE = int(os.environ.get('MAX_DOWNLOAD_SIZE', 50 * 1024 * 1024))  # 50MB
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    RATE_LIMIT_STORAGE_URL = REDIS_URL
    LOG_FILE = os.path.join(os.environ.get('PLUGIN_DIR', '/var/www/plugins'), 'access.log')

app = Flask(__name__)
app.config.from_object(Config)

# Initialize rate limiter with Redis backend
limiter = Limiter(
    app,
    key_func=get_remote_address,
    storage_uri=app.config['RATE_LIMIT_STORAGE_URL'],
    default_limits=["100 per hour"]
)

# Redis client for additional rate limiting and caching
try:
    redis_client = redis.from_url(app.config['REDIS_URL'])
    redis_client.ping()
except:
    redis_client = None
    print("Warning: Redis not available, falling back to basic rate limiting")

def log_access(action, ip, success=True, details=""):
    """Log access attempts with timestamp"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    status = "SUCCESS" if success else "FAILED"
    log_entry = f"{timestamp} | {ip} | {action} | {status} | {details}\n"
    
    try:
        with open(app.config['LOG_FILE'], 'a') as f:
            f.write(log_entry)
    except Exception as e:
        app.logger.error(f"Failed to write log: {e}")

def get_client_ip():
    """Get the real client IP address"""
    # Check for forwarded headers
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    elif request.headers.get('X-Client-IP'):
        return request.headers.get('X-Client-IP')
    else:
        return request.remote_addr

def require_auth(f):
    """Decorator to require bearer token authentication"""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization', '')
        expected_token = f"Bearer {app.config['AUTH_TOKEN']}"
        
        if not auth_header or auth_header != expected_token:
            log_access('AUTH_FAILED', get_client_ip(), False, f"Invalid token: {auth_header[:20]}...")
            abort(401)
        
        return f(*args, **kwargs)
    return decorated

def verify_jar_file(file_path):
    """Verify that the file is a valid JAR file"""
    try:
        if os.path.getsize(file_path) > app.config['MAX_DOWNLOAD_SIZE']:
            return False, "File too large"
        
        mime_type, _ = mimetypes.guess_type(file_path)
        if mime_type not in ['application/java-archive', 'application/zip']:
            return False, "Invalid file type"
        
        with open(file_path, 'rb') as f:
            signature = f.read(4)
            if signature != b'PK\x03\x04':
                return False, "Not a valid ZIP/JAR file"
        
        return True, "Valid JAR file"
    except Exception as e:
        return False, f"Verification error: {str(e)}"

def custom_rate_limit_check():
    """Additional rate limiting logic using Redis"""
    if not redis_client:
        return True
    
    client_ip = get_client_ip()
    current_time = int(time.time())
    window = 300
    max_requests = 20
    
    key = f"rate_limit:{client_ip}"
    
    try:
        pipe = redis_client.pipeline()
        pipe.zremrangebyscore(key, 0, current_time - window)
        pipe.zcard(key)
        pipe.zadd(key, {str(current_time): current_time})
        pipe.expire(key, window)
        results = pipe.execute()
        
        request_count = results[1]
        
        if request_count >= max_requests:
            log_access('RATE_LIMITED', client_ip, False, f"Requests: {request_count}")
            return False
        
        return True
    except Exception as e:
        app.logger.error(f"Rate limit check error: {e}")
        return True

@app.before_request
def before_request():
    """Pre-request checks"""
    if not custom_rate_limit_check():
        abort(429)
    
    @app.after_request
    def after_request(response):
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        return response

@app.route('/version.txt', methods=['GET'])
@require_auth
@limiter.limit("10 per minute")
def get_version():
    """Get the current plugin version"""
    client_ip = get_client_ip()
    version_file = os.path.join(app.config['PLUGIN_DIR'], 'version.txt')
    
    try:
        if not os.path.exists(version_file):
            log_access('VERSION_NOT_FOUND', client_ip, False)
            abort(404)
        
        with open(version_file, 'r') as f:
            version = f.read().strip()
        
        log_access('VERSION_CHECK', client_ip, True, f"Version: {version}")
        
        response = app.response_class(
            response=version,
            mimetype='text/plain',
            headers={'Cache-Control': 'no-cache, must-revalidate'}
        )
        return response
        
    except Exception as e:
        log_access('VERSION_ERROR', client_ip, False, str(e))
        app.logger.error(f"Version check error: {e}")
        abort(500)

@app.route('/download.jar', methods=['GET'])
@require_auth
@limiter.limit("5 per minute")
def download_plugin():
    """Download the plugin JAR file"""
    client_ip = get_client_ip()
    plugin_file = os.path.join(app.config['PLUGIN_DIR'], 'plugin.jar')
    
    try:
        if not os.path.exists(plugin_file):
            log_access('DOWNLOAD_NOT_FOUND', client_ip, False)
            abort(404)
        
        is_valid, message = verify_jar_file(plugin_file)
        if not is_valid:
            log_access('INVALID_FILE', client_ip, False, message)
            abort(403)
        
        file_size = os.path.getsize(plugin_file)
        log_access('DOWNLOAD_SUCCESS', client_ip, True, f"Size: {file_size} bytes")
        
        return send_file(
            plugin_file,
            as_attachment=True,
            download_name='plugin.jar',
            mimetype='application/java-archive',
            conditional=False
        )
        
    except FileNotFoundError:
        log_access('DOWNLOAD_NOT_FOUND', client_ip, False)
        abort(404)
    except Exception as e:
        log_access('DOWNLOAD_ERROR', client_ip, False, str(e))
        app.logger.error(f"Download error: {e}")
        abort(500)

@app.route('/health', methods=['GET'])
@limiter.limit("30 per minute")
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    })

@app.route('/stats', methods=['GET'])
@require_auth
@limiter.limit("5 per minute")
def get_stats():
    """Get server statistics (admin only)"""
    client_ip = get_client_ip()
    
    try:
        plugin_file = os.path.join(app.config['PLUGIN_DIR'], 'plugin.jar')
        version_file = os.path.join(app.config['PLUGIN_DIR'], 'version.txt')
        
        stats = {
            'plugin_exists': os.path.exists(plugin_file),
            'plugin_size': os.path.getsize(plugin_file) if os.path.exists(plugin_file) else 0,
            'current_version': '',
            'last_modified': None,
            'server_time': datetime.now().isoformat()
        }
        
        if os.path.exists(version_file):
            with open(version_file, 'r') as f:
                stats['current_version'] = f.read().strip()
        
        if os.path.exists(plugin_file):
            stats['last_modified'] = datetime.fromtimestamp(
                os.path.getmtime(plugin_file)
            ).isoformat()
        
        log_access('STATS_CHECK', client_ip, True)
        return jsonify(stats)
        
    except Exception as e:
        log_access('STATS_ERROR', client_ip, False, str(e))
        app.logger.error(f"Stats error: {e}")
        abort(500)

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({'error': 'Unauthorized'}), 401

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(429)
def rate_limit_exceeded(error):
    return jsonify({'error': 'Rate limit exceeded'}), 429

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

def init_app():
    """Initialize the application"""
    os.makedirs(app.config['PLUGIN_DIR'], exist_ok=True)
    
    version_file = os.path.join(app.config['PLUGIN_DIR'], 'version.txt')
    if not os.path.exists(version_file):
        with open(version_file, 'w') as f:
            f.write('1.0.0')
    
    if not app.debug:
        import logging
        from logging.handlers import RotatingFileHandler
        
        log_dir = os.path.join(app.config['PLUGIN_DIR'], 'logs')
        os.makedirs(log_dir, exist_ok=True)
        
        file_handler = RotatingFileHandler(
            os.path.join(log_dir, 'server.log'),
            maxBytes=10240000,  # 10MB
            backupCount=5
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info('Plugin distribution server startup')

if __name__ == '__main__':
    init_app()
    
    # Development server (use gunicorn for production)
    app.run(
        host='127.0.0.1',
        port=5000,
        debug=False,
        threaded=True
    )