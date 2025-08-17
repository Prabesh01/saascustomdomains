from flask import Blueprint, render_template, request, url_for, redirect, session, g, flash, jsonify, Response
from functools import wraps
from myapp.database import *

import secrets

import requests
import os, json

script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
env_path = os.path.join(script_dir, '.env')

from dotenv import load_dotenv
load_dotenv(env_path)

from dns import resolver

views = Blueprint('views', __name__, static_folder='static', template_folder='templates')
caddy_api=os.getenv('caddy_api')

def login_required(f):
    @wraps(f)
    def wrapped_view(**kwargs):
        if "user" not in session:
            return redirect(url_for('views.login'))

        user = User.query.get(session["user"])
        if not user:
            session.clear()
            return redirect(url_for('views.login'))
        g.user = user

        return f( **kwargs)

    return wrapped_view

def api_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-KEY') or request.args.get('api_key')
        if not api_key:
            return jsonify({'error': 'API key is required','status':400}), 400

        upstream = Upstream.query.filter_by(secret=api_key).first()
        if not upstream:
            return jsonify({'error': 'Invalid API key provided','status':404}), 404

        g.upstream = upstream
        return f(*args, **kwargs)
    return decorated


@views.route('/login',methods=["GET", "POST"])
def login():
    if "user" in session:
        return redirect(url_for('views.upstreams'))

    auth = request.authorization
    if not auth:
        return ('Unauthorized', 401, {
            'WWW-Authenticate': 'Basic realm="Login Required"'
        })

    user = User.query.filter_by(username=request.authorization.username).first()
    if user:
        if user.check_password(request.authorization.password):
            session["user"] = user.username
            return redirect(url_for("views.upstreams"))
        else:
           return ('Unauthorized', 401, {
                'WWW-Authenticate': 'Basic realm="Invalid Password for the user!"'
            })

    new_user = User(username=request.authorization.username, password='meh')
    new_user.set_password(request.authorization.password)
    db.session.add(new_user)
    db.session.commit()

    r=requests.post(f"https://api.cloudflare.com/client/v4/zones/{os.getenv('cf_zone_id')}/dns_records", headers={"Authorization":f"Bearer {os.getenv('cf_api_key')}"}, json={"type":"CNAME","name":new_user.username,"content":request.host,"ttl": 3600,"proxied": False})
    if r.status_code!=200:
        db.session.delete(new_user)
        db.session.commit()
    else: session["user"] = new_user.username

    return redirect(url_for("views.upstreams"))


@views.route('/',methods=['GET', 'POST'])
@login_required
def upstreams():
    if request.method == 'POST':
        domain = request.form['domain'].lower()
        if Upstream.query.filter_by(domain=domain,user=g.user).first():
            flash('Upstream already exists', 'error')
        else:
            new_upstream = Upstream(
                user=g.user,
                domain=domain,
                secret=secrets.token_urlsafe(36)
            )
            db.session.add(new_upstream)
            db.session.commit()
            flash('Upstream added successfully', 'success')

    upstreams = g.user.upstreams
    return render_template('upstreams.html', upstreams=upstreams)

@views.post('/delete_upstream/<upstream_id>')
@login_required
def delete_upstream(upstream_id):
    upstream = Upstream.query.filter_by(id=upstream_id, user=g.user).first_or_404()

    domains = Domain.query.filter_by(upstream_id=upstream_id).all()
    for domain in domains:
        remove_caddy(domain.domain)
    Domain.query.filter_by(upstream_id=upstream_id).delete()

    db.session.delete(upstream)
    db.session.commit()

    flash('Upstream and its domains deleted successfully', 'success')
    return redirect(url_for('views.upstreams'))

@views.get('/logout')
def logout():
    session.clear()
    return redirect(url_for('views.login'))

@views.get('/api')
@api_auth
def test_api():
    return jsonify({'message':'OK','status':200}), 200

@views.route('/upstream/<upstream_id>',methods=['GET', 'POST'])
@login_required
def domains(upstream_id):
    upstream = Upstream.query.filter_by(id=upstream_id, user=g.user).first_or_404()
    return render_template('domains.html', upstream=upstream, host=request.host)

@views.route('/api/domains',methods=['GET'])
@api_auth
def list_domains():
    domains = [d.domain for d in g.upstream.domains]
    return jsonify(domains)

@views.route('/api/domains',methods=['POST'])
@api_auth
def add_domain():
    domain = request.get_json().get('domain').lower()
    if not domain:
        return jsonify({'error': 'Domain is required','status':400}), 400

    if Domain.query.filter_by(domain=domain,upstream=g.upstream).first():
        return jsonify({'error': 'Domain already exists','status':409}), 409

    cname_check = add_caddy(session['user']+'.'+request.host, domain, g.upstream.domain)
    if cname_check:
        return jsonify({'error': cname_check,'status':400}), 400

    new_domain = Domain(
        upstream=g.upstream,
        domain=domain,
    )
    db.session.add(new_domain)
    db.session.commit()

    return jsonify({'message':'added successfully','status':200}), 200


@views.route('/api/domains',methods=['DELETE'])
@api_auth
def delete_domain():
    domain = request.get_json().get('domain')
    if not domain:
        return jsonify({'error': 'Domain is required','status':400}), 400

    domain = Domain.query.filter_by(domain=domain,upstream=g.upstream).first()
    if not domain:
        return jsonify({'error': 'Domain not found','status':404}), 404

    db.session.delete(domain)
    db.session.commit()

    remove_caddy(domain.domain)

    return jsonify({'message': 'Domain deleted','status':200}), 200


@views.get('/docs')
def docs():
    return render_template('docs.html',host=request.host)

def add_caddy(cname, domain,upstream):
    try: cnames=resolver.resolve(domain,"CNAME")
    except resolver.NXDOMAIN: return 'Invalid Domain Name'
    except: return "No CNAME record found in the domain. Please add and try again"
    if not any(r.target.to_text().rstrip(".") == cname for r in cnames): return "Required CNAME is not set. Please try again later."
    if Domain.query.filter_by(domain=domain).first(): remove_caddy(domain)
    route_data = {
        "match": [{"host": [domain]}],
        "handle": [
            {
                "handler": "reverse_proxy",
                "upstreams": [{"dial": upstream+":443"}],
                "transport": {"protocol": "http", "tls": {}}
            }
        ]
    }
    requests.post(f"{caddy_api}/config/apps/http/servers/srv0/routes", json=route_data)

    return False

def remove_caddy(domain):
    routes=requests.get(f"{caddy_api}/config/apps/http/servers/srv0/routes").json()
    for i, route in enumerate(routes):
        if domain in route['match'][0]['host']:
            requests.delete(f"{caddy_api}/config/apps/http/servers/srv0/routes/{i}")
            return

