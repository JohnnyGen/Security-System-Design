# Importazione delle librerie necessarie per la web app
from flask import Flask, flash, render_template, request, redirect, session
import requests  # Per effettuare richieste HTTP a Vault
import secrets  # Per generare token sicuri
from flask_sqlalchemy import SQLAlchemy  # ORM per gestire il database SQLite
from datetime import datetime, timedelta  # Per la gestione delle date e delle sessioni
import logging  # Per la registrazione degli eventi di sistema
from form import LoginForm, ThemeForm, NoteForm, DeleteNoteForm, NotificationForm  # Form gestiti con Flask-WTF
from flask_wtf.csrf import CSRFProtect  # Protezione CSRF contro attacchi web
from markupsafe import escape  # Sanitizzazione input utente per prevenire XSS
from werkzeug.exceptions import BadRequest  # Per gestire errori nelle richieste
import logging_manager  # Modulo per gestire logging e auditing
import XACML.vakt_manager  # Implementazione del motore ABAC per i permessi
import json
import jsonschema  # Validazione JSON
import re  # Per validazione degli input utente


# Creazione dell'app Flask
app = Flask(__name__)

# Genera una chiave segreta per proteggere le sessioni 
# Generiamo una chiave casuale a 32 bit che serve a Flask per firmare le sessioni e proteggerle da manomissioni. Ogni volta che lanciamo viene generata una chiave diversa
app.secret_key = secrets.token_hex(32)

# Abilita la protezione CSRF su tutta l'applicazione
csrf = CSRFProtect(app)

# Configurazione della gestione delle sessioni
MAX_SESSIONS = 1  # Numero massimo di sessioni per utente
SESSION_TIMEOUT = timedelta(minutes=10)  # Timeout delle sessioni per inattività


# Configurazione Vault (dove sono memorizzati i segreti e le credenziali)
VAULT_ADDR = "https://127.0.0.1:8200"  # Indirizzo di HashiCorp Vault
VAULT_VERIFY = False  # Disabilita la verifica SSL (da impostare a True in produzione)

# Configurazione del database SQLite per la gestione delle note
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///notes.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SESSION_COOKIE_SECURE'] = True  # Imposta i cookie di sessione come sicuri
db = SQLAlchemy(app)


logging.basicConfig(level=logging.DEBUG)

# Memorizza la policy in VAKT
storage = XACML.vakt_manager.vakt.MemoryStorage()
storage.add(XACML.vakt_manager.policy_note)
storage.add(XACML.vakt_manager.policy_theme_non_manager_deny)
storage.add(XACML.vakt_manager.policy_theme)
storage.add(XACML.vakt_manager.policy_theme_all_users_allow)
guard = XACML.vakt_manager.vakt.Guard(storage, XACML.vakt_manager.vakt.RulesChecker())

# Definizione del modello Note per memorizzare le note degli utenti nel database
class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Identificativo univoco della nota
    content = db.Column(db.String(500), nullable=False)  # Contenuto della nota
    username = db.Column(db.String(100), nullable=False)  # Nome utente a cui appartiene la nota

    def __repr__(self):
        return f"<Note {self.id} - {self.username}>"


# Definizione del modello Notification per salvare notifiche relative agli utenti
class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(500), nullable=False)  # Testo della notifica
    username = db.Column(db.String(100), nullable=False)  # Utente destinatario della notifica
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)  # Timestamp della notifica

    def __repr__(self):
        return f"<Notification {self.id} - {self.username}>"
    

# Modello per tracciare le sessioni attive degli utenti
class ActiveSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(100), nullable=False)  # ID utente associato alla sessione
    session_id = db.Column(db.String(100), nullable=False, unique=True)  # Identificativo univoco della sessione
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Timestamp di creazione della sessione

    def __repr__(self):
        return f"<ActiveSession {self.user_id} - {self.session_id}>"


# Creazione delle tabelle del database all'avvio dell'applicazione
with app.app_context():
    db.create_all()


# Funzione per creare una nuova notifica per un utente specifico
def create_notification(username, message):
    notification = Notification(username=username, message=message)
    db.session.add(notification)
    db.session.commit()


# Definizione di uno schema JSON per validare i dati di risposta da Vault (assicurarsi che il client token sia presente)
vault_response_schema = {
    "type": "object",
    "properties": {
        "auth": {
            "type": "object",
            "properties": {
                "client_token": {"type": "string"},
            },
            "required": ["client_token"],
        }
    },
    "required": ["auth"]
}

# Controllare il timeout delle sessioni prima di ogni richiesta
@app.before_request
def check_session_timeout():
    if "last_activity" in session:
        last_activity = session["last_activity"]

        # Se last_activity è una stringa, convertila in datetime naive
        if isinstance(last_activity, str):
            last_activity = datetime.strptime(last_activity, "%Y-%m-%d %H:%M:%S")

        # Rimuove il fuso orario se è presente
        if last_activity.tzinfo is not None:
            last_activity = last_activity.replace(tzinfo=None)

        # Controlla se la sessione è scaduta
        if datetime.now() - last_activity > SESSION_TIMEOUT:
            logging.info(f"Sessione scaduta per inattività. Utente: {session.get('username')}, session_id: {session.get('session_id')}.")
            flash("La tua sessione è scaduta per inattività.", "error")
            return logout()  # Termina la sessione ed effettua il logout
        
        # Aggiorna il timestamp nella sessione
        session["last_activity"] = datetime.now()



# Route principale per il login degli utenti

@app.route("/", methods=["GET", "POST"])
def index():
    form = LoginForm()
    if form.validate_on_submit():  # Se il form è valido
        if "access_token" in session:
            return redirect("/dashboard")
        else:
            return redirect("/")
    return render_template("login.html", form=form)


# Route per la gestione del login
@app.route("/login", methods=["POST"])
def login():

    # Recupera le credenziali inserite dall'utente nel form di login

    username = request.form.get("username")
    password = request.form.get("password")
    
    timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    # Costruisce l'URL per l'autenticazione con Vault via LDAP
    url = f"{VAULT_ADDR}/v1/auth/ldap/login/{username}"
    # Crea il payload per la richiesta HTTP (invia solo la password)
    payload = {"password": password}

    try:
        # Imposta header per indicare il formato JSON e prevenire vulnerabilità legate a Content-Type
        headers = {"Content-Type": "application/json"}

        # Autenticazione con Vault via LDAP: invia username e password
        response = requests.post(url, json=payload, headers=headers, verify=VAULT_VERIFY)
        # Se la richiesta HTTP fallisce (ad esempio, credenziali errate), genera un'eccezione
        response.raise_for_status()

        # Converte la risposta di Vault in un dizionario Python
        data = response.json()
        # Validazione della risposta di Vault rispetto allo schema JSON atteso
        jsonschema.validate(instance=data, schema=vault_response_schema)

        #TOKEN DI AUTENTICAZIONE DA VAULT (protezione accessi)
        #Se l'autenticazione ha successo Vault risponde con un token di autenticazione
        #Vault autentica l'utente e restituisce un client_token che rappresenta la sessione autenticata.
        # Viene salvato il token per ogni richiesta successiva si usa il token per recuperare informazioni da vault 
        session["vault_token"] = data["auth"]["client_token"]
        session["username"] = username
        session["last_activity"] = datetime.now()

        # Genera un identificativo univoco per la sessione dell'utente        
        session_id = secrets.token_hex(16)

        # Verifica il numero di sessioni attive
        active_sessions = ActiveSession.query.filter_by(user_id=username).count()
        if active_sessions >= MAX_SESSIONS:
            logging.warning(f"Limite di sessioni raggiunto per l'utente {username}. Accesso negato.")
            logging_manager.log_login(username, timestamp, "sistema", None, False)
            flash("Limite di sessioni attive raggiunto. Disconnettiti da un'altra sessione.", "error")
            return redirect("/")

        # Registra la nuova sessione nel database per tenere traccia delle sessioni attive
        new_session = ActiveSession(user_id=username, session_id=session_id)
        db.session.add(new_session)
        db.session.commit()

        # Salva l'ID della sessione nella sessione Flask dell'utente
        session["session_id"] = session_id
        
        logging_manager.log_login(username, timestamp, "pagina di login", session["session_id"], True)

        # Recupero del tema e del ruolo
        role = "standard"
        theme = "light"

        #CHIAVE ACCESSO AI SEGRETI
        #Vault memorizza i segreti in un key value store. il client recupera questi segreti solo se autenticato
        # Costruisce l'URL per recuperare i dati aggiuntivi dell'utente da Vault (ruolo, tema)
        url = f"{VAULT_ADDR}/v1/kv/data/secret/webapp-ldap/{username}"
        # Invia richiesta GET a Vault usando il token ottenuto con il login
        headers = {"X-Vault-Token": session["vault_token"]}
        response = requests.get(url, headers=headers, verify=VAULT_VERIFY)

        if response.status_code == 200:
            # Validazione del JSON segreto
            secret_data = response.json().get("data", {}).get("data", {})
            if not isinstance(secret_data, dict):
                raise ValueError("La struttura del JSON segreto non è valida.")
            
            # Recupera il tema e il ruolo dal JSON, utilizzando valori predefiniti se non presenti
            theme = secret_data.get("theme", "light")
            role = secret_data.get("role", "standard")
            
        # Salva il tema e il ruolo nella sessione dell'utente
        session["theme"] = theme
        session["role"] = role

        return redirect("/dashboard")
    except requests.exceptions.RequestException as e:
        logging.error(f"Errore durante la richiesta a Vault: {e}")
        logging_manager.log_login(username, timestamp, "pagina di login", 0, False)
        flash("Credenziali non valide. Riprova.", "error")
        return redirect("/")
    except jsonschema.exceptions.ValidationError as e:
        logging.error(f"JSON non valido ricevuto da Vault: {e}")
        logging_manager.log_login(username, timestamp, "pagina di login", 0, False)
        flash("Errore del server. Contatta l'amministratore.", "error")
        return redirect("/")
    except ValueError as e:
        logging.error(f"Errore nella struttura JSON segreta: {e}")
        logging_manager.log_login(username, timestamp, "pagina di login", 0, False)
        flash("Errore del server. Contatta l'amministratore.", "error")
        return redirect("/")


# Route per la dashboard, accessibile solo agli utenti autenticati
@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "vault_token" not in session:  # Controlla se l'utente è autenticato
        return redirect("/") # Se non autenticato, reindirizza al login

    # Recupera le informazioni dalla sessione
    theme = session.get("theme", "light") # Tema utente (default: light)
    username = session["username"]
    role = session.get("role", "standard") # Ruolo utente (default: standard)

    if request.method == "POST":
        new_theme = request.form.get("theme")  # Nuovo tema scelto dall'utente
        
        # Verifica che il valore del tema sia valido
        if not new_theme or not re.match("^[a-zA-Z0-9_-]+$", new_theme):
            flash("Tema non valido. Scegli un tema valido.", "error")
            return redirect("/dashboard")
        
        try:
            # Recupera i dati utente memorizzati in Vault
            url = f"{VAULT_ADDR}/v1/kv/data/secret/webapp-ldap/{username}"
            headers = {"X-Vault-Token": session["vault_token"]}
            response = requests.get(url, headers=headers, verify=VAULT_VERIFY)
            response.raise_for_status()

            # Estrarre i dati del segreto
            data = response.json()
            jsonschema.validate(instance=data, schema=vault_response_schema)  

            # Dump dei dati JSON ricevuti (per log e debug)
            secret_data = data.get("data", {}).get("data", {})
            json_data = json.dumps(secret_data, indent=4)  # Serializzazione del JSON
            logging.info(f"JSON ricevuto da Vault: {json_data}")  # Log del JSON

            # Verifica che i dati siano nel formato corretto prima di aggiornarli
            if not isinstance(secret_data, dict):
                raise ValueError("La struttura del JSON segreto non è valida.")
            
            # Aggiorna il valore del tema
            secret_data["theme"] = new_theme

            # Verifica che l'utente abbia il permesso di cambiare il tema
            if role == "admin" or role == "standard":
                payload = {"data": secret_data}

                # Validazione JSON per il payload
                try:
                    json.dumps(payload)  # Verifica che il payload sia serializzabile in JSON
                except (TypeError, ValueError) as e:
                    raise BadRequest(f"Errore di serializzazione JSON: {e}")

                response = requests.post(url, headers=headers, json=payload, verify=VAULT_VERIFY)
                response.raise_for_status()

                session["theme"] = new_theme
            else:
                flash("Non hai i permessi per modificare il tema.", "error")

        except requests.exceptions.RequestException as e:
            flash(f"Failed to update theme: {e}", "error")
            return redirect("/dashboard")
        except BadRequest as e:
            flash(f"Errore nella richiesta: {e}", "error")
            return redirect("/dashboard")
        except jsonschema.exceptions.ValidationError as e:
            logging.error(f"JSON non valido ricevuto da Vault: {e}")
            flash("Errore del server. Contatta l'amministratore.", "error")
            return redirect("/dashboard")
        except ValueError as e:
            logging.error(f"Errore nella struttura JSON segreta: {e}")
            flash("Errore del server. Contatta l'amministratore.", "error")
            return redirect("/dashboard")

    # Rendi visibile il tema e il ruolo nella dashboard
    return render_template("dashboard.html", username=username, theme=theme, role=role)


@app.route("/account-settings", methods=["GET", "POST"])
def account_settings():
    if "vault_token" not in session:  # Verifica se l'utente è autenticato
        return redirect("/")  # Se no, reindirizza al login

    username = session["username"]
    role = session.get("role", "standard")
    theme = session.get("theme", "light")
    
    timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    current_time = datetime.now().strftime("%H:%M:%S")  # Ottieni l'orario corrente

    # Verifica solo se si tenta di modificare il tema
    if request.method == "POST" and 'theme' in request.form:
        inquiry = XACML.vakt_manager.vakt.Inquiry(
            action='modify',
            resource='theme',
            subject={'role': session['role']}, 
            context={'current_time': current_time}
        )

        if not guard.is_allowed(inquiry):  # Se la policy non consente, blocca l'accesso
            logging_manager.theme(username, timestamp, "account settings", session["session_id"], False)
            flash("Non hai i permessi per modificare il tema in questo momento.", "error")
            return redirect("/dashboard")  # Reindirizza alla dashboard se la modifica non è consentita

    form = ThemeForm()

    if request.method == "POST" and form.validate_on_submit(): #form valido
        new_theme = form.theme.data
        try:
            #recupero del segreto da vault
            url = f"{VAULT_ADDR}/v1/kv/data/secret/webapp-ldap/{username}"
            headers = {"X-Vault-Token": session["vault_token"]}
            response = requests.get(url, headers=headers, verify=VAULT_VERIFY)
            response.raise_for_status()

            #estrazione dei dati memorizzati
            secret_data = response.json().get("data", {}).get("data", {})
            secret_data["theme"] = new_theme
            payload = {"data": secret_data}

            #aggiornamento del tema
            response = requests.post(url, headers=headers, json=payload, verify=VAULT_VERIFY)
            response.raise_for_status()

            #aggiorna la sessione
            session["theme"] = new_theme  # Aggiorna il tema nella sessione
            session["last_activity"] = datetime.now()
            
            logging_manager.theme(username, timestamp, "account settings", session["session_id"], True)
            flash("Tema modificato con successo!", "success")
        except requests.exceptions.RequestException as e:
            logging_manager.theme(username, timestamp, "sistema", session["session_id"], False)
            flash(f"Errore nell'aggiornamento del tema: {e}", "error")

    return render_template("account_settings.html", username=username, role=role, theme=theme, form=form)

# Route per gestire le notifiche dell'utente
@app.route("/notifications", methods=["GET", "POST"])
def notifications():
    if "vault_token" not in session:
        return redirect("/")

    username = session["username"]
    theme = session.get("theme", "light")
    
    # Ottieni le notifiche dell'utente dal database
    user_notifications = Notification.query.filter_by(username=username).order_by(Notification.timestamp.desc()).all()
    
    # Crea un oggetto form per la cancellazione di tutte le notifiche
    form = NotificationForm()
    
    # Eliminazione di tutte le notifiche se richiesto dall'utente 
    if form.submit_clear_all.data and form.validate_on_submit():
        Notification.query.filter_by(username=username).delete()
        db.session.commit()
        session["last_activity"] = datetime.now()
        flash("Tutte le notifiche sono state eliminate.", "success")
        return redirect("/notifications")

    # Per ogni notifica, crea un form per eliminarla singolarmente
    form_delete = {}
    for notification in user_notifications:
        form_delete[notification.id] = NotificationForm()
        session["last_activity"] = datetime.now()

    return render_template("notifications.html", 
                           notifications=user_notifications, 
                           theme=theme,
                           form=form,
                           form_delete=form_delete)

@app.route("/notifications/clear-all", methods=["POST"])
def clear_all_notifications():
    if "username" not in session:
        return redirect("/")
    
    username = session["username"]
    # Elimina tutte le notifiche dell'utente
    Notification.query.filter_by(username=username).delete()
    db.session.commit()
    
    flash("Tutte le notifiche sono state eliminate.", "success")
    return redirect("/notifications")

@app.route("/notifications/delete/<int:id>", methods=["POST"])
def delete_notification(id):
    if "username" not in session:
        return redirect("/")

    # Recupera la notifica per l'ID fornito
    notification = Notification.query.get(id)
    if notification:
        db.session.delete(notification)
        db.session.commit()
        flash("Notifica eliminata.", "success")
    else:
        flash("Notifica non trovata.", "error")
    
    return redirect("/notifications")

@app.route("/notes")
def notes():
    if "vault_token" not in session:
        return redirect("/")

    username = session["username"]
    role = session.get("role", "standard")
    theme = session.get("theme", "light")
    form = DeleteNoteForm()

    if role == "admin" or role == "manager":
        all_notes = Note.query.all()
        session["last_activity"] = datetime.now()
    else:
        all_notes = Note.query.filter_by(username=username).all()
        session["last_activity"] = datetime.now()

    return render_template("notes.html", notes=all_notes, role=role, theme=theme, form=form)

@app.route("/add-note", methods=["GET", "POST"])
def add_note():
    if "vault_token" not in session:
        return redirect("/")

    role = session.get("role", "standard")
    theme = session.get("theme", "light")
    timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    form = NoteForm()  # Usa il NoteForm per gestire il modulo
    
    if request.method == "POST":
        current_time = datetime.now().strftime("%H:%M:%S")
        inquiry = XACML.vakt_manager.vakt.Inquiry(
            action='modify',
            resource='note',
            subject={'username': session['username']},
            context={'current_time': current_time}
        )
        session["last_activity"] = datetime.now()

        if guard.is_allowed(inquiry):
            
            if form.validate_on_submit():  # Verifica che il modulo sia valido
                content = form.content.data  # Ottieni il contenuto dal form
                # Escape il contenuto per evitare XSS
                safe_content = escape(content)
                username = session["username"]
                
                new_note = Note(content=safe_content, username=username)
                db.session.add(new_note)
                db.session.commit()
                
                # Log dell'azione
                logging_manager.log_audit(username, 'creazione', 'note', timestamp, session['session_id'], 'successo')

                create_notification(username, f"Hai aggiunto una nuova nota: '{safe_content}'")
                create_notification("admin", f"Nota aggiunta da {username}: '{safe_content}'")
                
                flash("Nota aggiunta con successo!", "success")
                return redirect("/notes")                
        else:
            logging.warning(f"Accesso negato: policy restrictiva. Utente: {session['username']}, Azione: {inquiry.action}, Risorsa: {inquiry.resource}.")
            logging_manager.log_audit(session["username"], 'creazione', 'note', timestamp, session['session_id'], 'fallimento')
            flash("Non hai i permessi per aggiungere una nota in questo momento.", "error")

    return render_template("add_note.html", form=form, role=role, theme=theme)

@app.route("/edit-note/<int:id>", methods=["GET", "POST"])
def edit_note(id):
    if "vault_token" not in session:
        return redirect("/")

    note = Note.query.get_or_404(id)  # Recupera la nota dal DB
    form = NoteForm(obj=note)  # Usa il form per pre-popolare il campo con il contenuto attuale
    username = session["username"]
    role = session.get("role", "standard")
    theme = session.get("theme", "light")
    
    timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    # Verifica se l'utente ha il permesso di modificare la nota
    if note.username != username and role != "admin":
        flash("Non hai i permessi per modificare questa nota.", "error")
        return redirect("/notes")

    if request.method == "POST":
        current_time = datetime.now().strftime("%H:%M:%S")
        inquiry = XACML.vakt_manager.vakt.Inquiry(
            action='modify',
            resource='note',
            subject={'username': session['username']},
            context={'current_time': current_time}
        )
        session["last_activity"] = datetime.now()

        if guard.is_allowed(inquiry):  # Verifica se l'utente ha il permesso tramite guard
            if form.validate_on_submit():  # Se il form è valido
                old_content = note.content  # Memorizza il contenuto precedente
                note.content = form.content.data  # Aggiorna il contenuto con quello del form
                db.session.commit()  # Salva i cambiamenti nel DB
                
                # Log dell'azione
                logging_manager.log_audit(username, 'modifica', 'note', timestamp, session['session_id'], 'successo')

                # Notifica dell'aggiornamento
                create_notification(note.username, f"Hai modificato una tua nota: '{old_content}' in '{note.content}'")

                flash("Nota modificata con successo!", "success")
                return redirect("/notes")
        else:
            logging.warning(f"Accesso negato: policy restrittiva. Utente: {session['username']}, Azione: {inquiry.action}, Risorsa: {inquiry.resource}.")
            logging_manager.log_audit(session["username"], 'modifica', 'note', timestamp, session['session_id'],'fallimento')
            flash("Non hai i permessi per modificare questa nota in questo momento.", "error")

    return render_template("edit_note.html", form=form, note=note, theme=theme)

@app.route("/delete-note/<int:id>", methods=["POST"])
def delete_note(id):
    if "vault_token" not in session:
        return redirect("/")

    note = Note.query.get_or_404(id)
    username = session["username"]
    role = session.get("role", "standard")
    timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")

    if note.username != username and role != "admin":
        flash("Non hai i permessi per eliminare questa nota.", "error")
        return redirect("/notes")

    # Crea il form di delete
    form = DeleteNoteForm()

    if form.validate_on_submit():  # Gestisce il CSRF automaticamente
        current_time = datetime.now().strftime("%H:%M:%S")
        inquiry = XACML.vakt_manager.vakt.Inquiry(
            action='modify',
            resource='note',
            subject={'username': session['username']},
            context={'current_time': current_time}
        )
        session["last_activity"] = datetime.now()

        if guard.is_allowed(inquiry):
            content = note.content
            db.session.delete(note)
            db.session.commit()
            
            # Log dell'azione
            logging_manager.log_audit(username, 'eliminazione', 'note', current_time, session['session_id'], 'successo')

            create_notification(note.username, f"Hai eliminato una tua nota: '{content}'")
            create_notification("admin", f"Nota eliminata da {username}: '{content}'")

            flash("Nota eliminata con successo!", "success")
            return redirect("/notes")
        else:
            logging.warning(f"Accesso negato: policy restrittiva. Utente: {session['username']}, Azione: {inquiry.action}, Risorsa: {inquiry.resource}.")
            flash("Non hai i permessi per eliminare questa nota in questo momento.", "error")
            return redirect("/notes")
    else:
        logging_manager.log_audit(session["username"], 'eliminazione', 'note', timestamp, session['session_id'], 'fallimento')
        flash("Errore nel tentativo di eliminare la nota.", "error")
        return redirect("/notes")

@app.route("/logout")
def logout():
    session_id = session.get("session_id")
    if session_id:
        ActiveSession.query.filter_by(session_id=session_id).delete()
        db.session.commit()
        
    current_time = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    logging_manager.logout(session["username"], current_time, "sistema", session["session_id"])

    session.clear()
    return redirect("/")

if __name__ == "__main__":
    #Certificati SSL locali per abilitare HTTPS
    context = ('C:/Users/forma/Desktop/SSD/HW4/Config/localhost.crt', 'C:/Users/forma/Desktop/SSD/HW4/Config/private_key.key')
    app.run(debug=True, host="0.0.0.0", port=5000, ssl_context=context)