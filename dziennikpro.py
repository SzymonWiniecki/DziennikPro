
from flask import Flask, request, redirect, url_for, render_template_string, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "tajny_klucz"

# Dane testowe
users = {
    "admin": {"haslo": generate_password_hash("admin123"), "rola": "admin"},
    "nauczyciel": {"haslo": generate_password_hash("nauczyciel123"), "rola": "teacher"},
    "uczen1": {"haslo": generate_password_hash("uczen123"), "rola": "student"},
}

students = {
    "uczen1": {"oceny": [], "zadania": [], "wiadomosci": []}
}

teachers = {
    "nauczyciel": {"wiadomosci": []}
}

aktualnosci = [
    "Witamy w DziennikuPro!",
    "Przypominamy o zebraniu rodziców w piątek."
]

zadania_domowe = [
    {"tytul": "Matematyka - zadania z ułamków", "termin": "2025-09-15"},
    {"tytul": "Historia - notatka o II wojnie", "termin": "2025-09-18"}
]

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        login = request.form["login"]
        haslo = request.form["haslo"]
        user = users.get(login)
        if user and check_password_hash(user["haslo"], haslo):
            session["user"] = login
            session["rola"] = user["rola"]
            return redirect(url_for("panel"))
        flash("Błędny login lub hasło")
    return render_template_string("""
        <h2>DziennikPro - Logowanie</h2>
        <form method="post">
          Login: <input name="login"><br>
          Hasło: <input name="haslo" type="password"><br>
          <button type="submit">Zaloguj</button>
        </form>
    """)

@app.route("/panel")
def panel():
    if "user" not in session:
        return redirect(url_for("index"))
    rola = session["rola"]
    if rola == "admin":
        return redirect(url_for("panel_admina"))
    elif rola == "teacher":
        return redirect(url_for("panel_nauczyciela"))
    else:
        return redirect(url_for("panel_ucznia"))

@app.route("/admin")
def panel_admina():
    return render_template_string("<h2>Panel Administratora</h2><p>Tu będzie panel administracyjny.</p>")

@app.route("/nauczyciel")
def panel_nauczyciela():
    return render_template_string("""
        <h2>Panel Nauczyciela</h2>
        <a href="{{ url_for('wiadomosci') }}">Wiadomości</a><br>
        <ul>
        {% for a in aktualnosci %}
          <li>{{ a }}</li>
        {% endfor %}
        </ul>
    """, aktualnosci=aktualnosci)

@app.route("/uczen")
def panel_ucznia():
    user = session["user"]
    return render_template_string("""
        <h2>Panel Ucznia</h2>
        <a href="{{ url_for('wiadomosci') }}">Wiadomości</a><br>
        <ul>
        {% for a in aktualnosci %}
          <li>{{ a }}</li>
        {% endfor %}
        </ul>
        <h3>Zadania domowe:</h3>
        <ul>
        {% for z in zadania %}
          <li>{{ z.tytul }} - do {{ z.termin }}</li>
        {% endfor %}
        </ul>
    """, aktualnosci=aktualnosci, zadania=zadania_domowe)

@app.route("/wiadomosci", methods=["GET", "POST"])
def wiadomosci():
    user = session["user"]
    role = session["rola"]
    rozmowa = request.args.get("rozmowa", "nauczyciel" if role == "student" else "uczen1")
    skrzynka = students.get("uczen1", {}).get("wiadomosci", []) + teachers.get("nauczyciel", {}).get("wiadomosci", [])

    if request.method == "POST":
        tresc = request.form["tresc"]
        wiadomosc = {"od": user, "do": rozmowa, "tresc": tresc}
        if role == "teacher":
            students[rozmowa]["wiadomosci"].append(wiadomosc)
        else:
            teachers[rozmowa]["wiadomosci"].append(wiadomosc)
        flash("Wiadomość wysłana")
        return redirect(url_for("wiadomosci", rozmowa=rozmowa))

    konwersacja = [w for w in skrzynka if (w["od"] == user and w["do"] == rozmowa) or (w["od"] == rozmowa and w["do"] == user)]
    return render_template_string("""
    <h2>Wiadomości z {{ rozmowa }}</h2>
    <ul>
      {% for w in konwersacja %}
        <li><b>{{ w.od }} → {{ w.do }}:</b> {{ w.tresc }}</li>
      {% endfor %}
    </ul>
    <form method="post">
      <textarea name="tresc" rows="3" cols="40" required></textarea><br>
      <button type="submit">Wyślij</button>
    </form>
    """, rozmowa=rozmowa, konwersacja=konwersacja)

if __name__ == "__main__":
    app.run(debug=True)
