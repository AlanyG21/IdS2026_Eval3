import sqlite3
import os
from datetime import datetime, date, timedelta
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
# En producción usar una variable de entorno segura
app.secret_key = os.environ.get("SECRET_KEY", "clave_secreta_hotel_rios_del_sur_2026")
DB_NAME = "hotel_rios_del_sur.db"

# Configuración de seguridad en cookies de sesión (OWASP)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    # Activar soporte de claves foráneas en SQLite
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn

def init_db():
    """Crea las tablas, restricciones y datos de prueba si la BD no existe."""
    if os.path.exists(DB_NAME):
        return

    conn = get_db()
    cursor = conn.cursor()

    cursor.executescript("""
    CREATE TABLE usuarios (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre VARCHAR(100) NOT NULL,
        email VARCHAR(120) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        rol VARCHAR(20) NOT NULL DEFAULT 'recepcionista' CHECK (rol IN ('admin', 'recepcionista')),
        activo BOOLEAN NOT NULL DEFAULT 1,
        creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE habitaciones (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        numero VARCHAR(10) UNIQUE NOT NULL,
        tipo VARCHAR(30) NOT NULL CHECK (tipo IN ('Single', 'Doble', 'Matrimonial', 'Suite')),
        capacidad INT NOT NULL CHECK (capacidad > 0),
        precio_noche DECIMAL(10, 2) NOT NULL CHECK (precio_noche > 0),
        estado VARCHAR(20) NOT NULL DEFAULT 'disponible' CHECK (estado IN ('disponible', 'ocupada', 'mantenimiento')),
        descripcion TEXT
    );

    CREATE TABLE huespedes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rut_pasaporte VARCHAR(20) UNIQUE NOT NULL,
        nombre_completo VARCHAR(150) NOT NULL,
        email VARCHAR(120) NOT NULL,
        telefono VARCHAR(25) NOT NULL,
        nacionalidad VARCHAR(50) DEFAULT 'Chilena',
        creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE reservas (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        huesped_id INT NOT NULL,
        habitacion_id INT NOT NULL,
        usuario_id INT NOT NULL,
        fecha_entrada DATE NOT NULL,
        fecha_salida DATE NOT NULL,
        estado VARCHAR(20) NOT NULL DEFAULT 'confirmada' CHECK (estado IN ('confirmada', 'en_curso', 'finalizada', 'cancelada')),
        total_pago DECIMAL(10, 2) NOT NULL CHECK (total_pago >= 0),
        observaciones TEXT,
        creado_en TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (huesped_id) REFERENCES huespedes(id) ON DELETE RESTRICT,
        FOREIGN KEY (habitacion_id) REFERENCES habitaciones(id) ON DELETE RESTRICT,
        FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE RESTRICT,
        CHECK (fecha_salida > fecha_entrada)
    );
    """)

    # Datos de prueba (Contraseña para ambos: Hotel2026!)
    admin_hash = generate_password_hash("Hotel2026!")
    recep_hash = generate_password_hash("Hotel2026!")

    cursor.executemany(
        "INSERT INTO usuarios (nombre, email, password_hash, rol) VALUES (?, ?, ?, ?)",
        [
            ("Administrador General", "admin@hotelriosdelsur.cl", admin_hash, "admin"),
            ("Camila Soto", "csoto@hotelriosdelsur.cl", recep_hash, "recepcionista"),
        ],
    )

    cursor.executemany(
        "INSERT INTO habitaciones (numero, tipo, capacidad, precio_noche, estado, descripcion) VALUES (?, ?, ?, ?, ?, ?)",
        [
            ("101", "Single", 1, 45000, "disponible", "Vista al jardín interior, 1 cama plaza y media."),
            ("102", "Doble", 2, 68000, "ocupada", "Dos camas individuales, escritorio y calefacción."),
            ("201", "Matrimonial", 2, 75000, "disponible", "Cama King, balcón con vista parcial al río."),
            ("202", "Suite", 4, 135000, "disponible", "Vista panorámica al río, sala de estar y jacuzzi."),
            ("301", "Doble", 2, 68000, "mantenimiento", "Mantención preventiva de calefacción."),
        ],
    )

    cursor.executemany(
        "INSERT INTO huespedes (rut_pasaporte, nombre_completo, email, telefono, nacionalidad) VALUES (?, ?, ?, ?, ?)",
        [
            ("18.456.789-2", "Matías Andrés Vargas Muñoz", "mvargas@correo.cl", "+56987654321", "Chilena"),
            ("15.987.654-K", "Valentina Paz Contreras Silva", "vcontreras@correo.cl", "+56912345678", "Chilena"),
            ("AAB458921", "Lucas Fernández", "lfernandez@mail.com.ar", "+5491145678901", "Argentina"),
        ],
    )

    hoy = date.today()
    cursor.executemany(
        "INSERT INTO reservas (huesped_id, habitacion_id, usuario_id, fecha_entrada, fecha_salida, estado, total_pago, observaciones) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (1, 2, 2, (hoy - timedelta(days=1)).isoformat(), (hoy + timedelta(days=2)).isoformat(), "en_curso", 204000, "Solicitó almohadas extra."),
            (2, 4, 2, (hoy + timedelta(days=5)).isoformat(), (hoy + timedelta(days=8)).isoformat(), "confirmada", 405000, "Aniversario, preparar bienvenida."),
            (3, 1, 1, (hoy - timedelta(days=10)).isoformat(), (hoy - timedelta(days=7)).isoformat(), "finalizada", 135000, "Sin novedades."),
        ],
    )

    conn.commit()
    conn.close()

# ============================================================================
# DECORADORES DE SEGURIDAD (OWASP: Broken Access Control)
# ============================================================================
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Debes iniciar sesión para acceder al sistema.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function

# ============================================================================
# RUTAS DE AUTENTICACIÓN
# ============================================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_db()
        user = conn.execute("SELECT * FROM usuarios WHERE email = ? AND activo = 1", (email,)).fetchone()
        conn.close()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["user_name"] = user["nombre"]
            session["user_rol"] = user["rol"]
            flash(f"Bienvenido/a, {user['nombre']}.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Credenciales inválidas o usuario inactivo.", "danger")

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Sesión cerrada correctamente.", "info")
    return redirect(url_for("login"))

# ============================================================================
# DASHBOARD Y CONSULTA DE DISPONIBILIDAD
# ============================================================================
@app.route("/")
@login_required
def dashboard():
    conn = get_db()
    stats = {
        "disponibles": conn.execute("SELECT COUNT(*) FROM habitaciones WHERE estado = 'disponible'").fetchone()[0],
        "ocupadas": conn.execute("SELECT COUNT(*) FROM habitaciones WHERE estado = 'ocupada'").fetchone()[0],
        "mantenimiento": conn.execute("SELECT COUNT(*) FROM habitaciones WHERE estado = 'mantenimiento'").fetchone()[0],
        "reservas_activas": conn.execute("SELECT COUNT(*) FROM reservas WHERE estado IN ('confirmada', 'en_curso')").fetchone()[0],
    }

    # Filtro de disponibilidad por rango de fechas
    fecha_inicio = request.args.get("fecha_inicio", "")
    fecha_fin = request.args.get("fecha_fin", "")
    habitaciones_disponibles = []

    if fecha_inicio and fecha_fin:
        if fecha_fin <= fecha_inicio:
            flash("La fecha de salida debe ser posterior a la fecha de entrada.", "danger")
        else:
            habitaciones_disponibles = conn.execute("""
                SELECT * FROM habitaciones
                WHERE estado != 'mantenimiento'
                  AND id NOT IN (
                      SELECT habitacion_id FROM reservas
                      WHERE estado IN ('confirmada', 'en_curso')
                        AND fecha_entrada < ?
                        AND fecha_salida > ?
                  )
                ORDER BY numero
            """, (fecha_fin, fecha_inicio)).fetchall()

    conn.close()
    return render_template(
        "dashboard.html",
        stats=stats,
        fecha_inicio=fecha_inicio,
        fecha_fin=fecha_fin,
        habitaciones_disponibles=habitaciones_disponibles,
    )

# ============================================================================
# GESTIÓN DE HABITACIONES
# ============================================================================
@app.route("/habitaciones", methods=["GET", "POST"])
@login_required
def habitaciones():
    conn = get_db()
    if request.method == "POST":
        numero = request.form.get("numero", "").strip()
        tipo = request.form.get("tipo", "")
        capacidad = request.form.get("capacidad", type=int)
        precio_noche = request.form.get("precio_noche", type=float)
        descripcion = request.form.get("descripcion", "").strip()

        if not numero or not capacidad or not precio_noche or capacidad <= 0 or precio_noche <= 0:
            flash("Datos inválidos. Verifica número, capacidad y precio.", "danger")
        else:
            try:
                conn.execute(
                    "INSERT INTO habitaciones (numero, tipo, capacidad, precio_noche, descripcion) VALUES (?, ?, ?, ?, ?)",
                    (numero, tipo, capacidad, precio_noche, descripcion),
                )
                conn.commit()
                flash(f"Habitación {numero} registrada exitosamente.", "success")
            except sqlite3.IntegrityError:
                flash(f"Error: La habitación {numero} ya existe o los datos no son válidos.", "danger")

    lista_habitaciones = conn.execute("SELECT * FROM habitaciones ORDER BY numero").fetchall()
    conn.close()
    return render_template("habitaciones.html", habitaciones=lista_habitaciones)

@app.route("/habitaciones/<int:id>/estado", methods=["POST"])
@login_required
def cambiar_estado_habitacion(id):
    nuevo_estado = request.form.get("estado")
    if nuevo_estado in ("disponible", "ocupada", "mantenimiento"):
        conn = get_db()
        conn.execute("UPDATE habitaciones SET estado = ? WHERE id = ?", (nuevo_estado, id))
        conn.commit()
        conn.close()
        flash("Estado de la habitación actualizado.", "success")
    return redirect(url_for("habitaciones"))

# ============================================================================
# GESTIÓN DE HUÉSPEDES
# ============================================================================
@app.route("/huespedes", methods=["GET", "POST"])
@login_required
def huespedes():
    conn = get_db()
    if request.method == "POST":
        rut_pasaporte = request.form.get("rut_pasaporte", "").strip().upper()
        nombre_completo = request.form.get("nombre_completo", "").strip()
        email = request.form.get("email", "").strip().lower()
        telefono = request.form.get("telefono", "").strip()
        nacionalidad = request.form.get("nacionalidad", "Chilena").strip()

        if not rut_pasaporte or not nombre_completo or not email or not telefono:
            flash("Todos los campos obligatorios deben completarse.", "danger")
        else:
            try:
                conn.execute(
                    "INSERT INTO huespedes (rut_pasaporte, nombre_completo, email, telefono, nacionalidad) VALUES (?, ?, ?, ?, ?)",
                    (rut_pasaporte, nombre_completo, email, telefono, nacionalidad),
                )
                conn.commit()
                flash("Huésped registrado correctamente.", "success")
            except sqlite3.IntegrityError:
                flash("Error: El RUT o Pasaporte ya se encuentra registrado.", "danger")

    lista_huespedes = conn.execute("SELECT * FROM huespedes ORDER BY nombre_completo").fetchall()
    conn.close()
    return render_template("huespedes.html", huespedes=lista_huespedes)

# ============================================================================
# GESTIÓN DE RESERVAS, CHECK-IN Y CHECK-OUT
# ============================================================================
@app.route("/reservas", methods=["GET", "POST"])
@login_required
def reservas():
    conn = get_db()
    if request.method == "POST":
        huesped_id = request.form.get("huesped_id", type=int)
        habitacion_id = request.form.get("habitacion_id", type=int)
        fecha_entrada = request.form.get("fecha_entrada", "")
        fecha_salida = request.form.get("fecha_salida", "")
        observaciones = request.form.get("observaciones", "").strip()

        try:
            d_in = datetime.strptime(fecha_entrada, "%Y-%m-%d").date()
            d_out = datetime.strptime(fecha_salida, "%Y-%m-%d").date()
            noches = (d_out - d_in).days

            if noches <= 0:
                flash("La fecha de salida debe ser posterior a la de entrada.", "danger")
            else:
                # Validar que la habitación no esté en mantenimiento ni tenga choque de fechas
                hab = conn.execute("SELECT * FROM habitaciones WHERE id = ?", (habitacion_id,)).fetchone()
                choque = conn.execute("""
                    SELECT id FROM reservas
                    WHERE habitacion_id = ?
                      AND estado IN ('confirmada', 'en_curso')
                      AND fecha_entrada < ?
                      AND fecha_salida > ?
                """, (habitacion_id, fecha_salida, fecha_entrada)).fetchone()

                if not hab or hab["estado"] == "mantenimiento":
                    flash("La habitación seleccionada no está operativa.", "danger")
                elif choque:
                    flash("Conflicto de fechas: La habitación ya está reservada en ese período.", "danger")
                else:
                    total_pago = noches * hab["precio_noche"]
                    conn.execute("""
                        INSERT INTO reservas (huesped_id, habitacion_id, usuario_id, fecha_entrada, fecha_salida, total_pago, observaciones)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    """, (huesped_id, habitacion_id, session["user_id"], fecha_entrada, fecha_salida, total_pago, observaciones))
                    conn.commit()
                    flash(f"Reserva creada por {noches} noche(s). Total: ${total_pago:,.0f}", "success")
        except ValueError:
            flash("Formato de fecha inválido.", "danger")

    lista_reservas = conn.execute("""
        SELECT r.*, h.nombre_completo AS huesped_nombre, h.rut_pasaporte,
               hab.numero AS hab_numero, hab.tipo AS hab_tipo, u.nombre AS usuario_nombre
        FROM reservas r
        JOIN huespedes h ON r.huesped_id = h.id
        JOIN habitaciones hab ON r.habitacion_id = hab.id
        JOIN usuarios u ON r.usuario_id = u.id
        ORDER BY r.id DESC
    """).fetchall()

    lista_huespedes = conn.execute("SELECT id, rut_pasaporte, nombre_completo FROM huespedes ORDER BY nombre_completo").fetchall()
    lista_habitaciones = conn.execute("SELECT id, numero, tipo, precio_noche FROM habitaciones WHERE estado != 'mantenimiento' ORDER BY numero").fetchall()
    conn.close()

    return render_template(
        "reservas.html",
        reservas=lista_reservas,
        huespedes=lista_huespedes,
        habitaciones=lista_habitaciones,
    )

@app.route("/reservas/<int:id>/accion/<string:accion>", methods=["POST"])
@login_required
def accion_reserva(id, accion):
    conn = get_db()
    reserva = conn.execute("SELECT * FROM reservas WHERE id = ?", (id,)).fetchone()

    if not reserva:
        flash("Reserva no encontrada.", "danger")
        conn.close()
        return redirect(url_for("reservas"))

    try:
        if accion == "checkin" and reserva["estado"] == "confirmada":
            conn.execute("UPDATE reservas SET estado = 'en_curso' WHERE id = ?", (id,))
            conn.execute("UPDATE habitaciones SET estado = 'ocupada' WHERE id = ?", (reserva["habitacion_id"],))
            flash("Check-in realizado. Habitación marcada como ocupada.", "success")

        elif accion == "checkout" and reserva["estado"] == "en_curso":
            conn.execute("UPDATE reservas SET estado = 'finalizada' WHERE id = ?", (id,))
            conn.execute("UPDATE habitaciones SET estado = 'disponible' WHERE id = ?", (reserva["habitacion_id"],))
            flash("Check-out realizado. Habitación liberada y disponible.", "success")

        elif accion == "cancelar" and reserva["estado"] == "confirmada":
            conn.execute("UPDATE reservas SET estado = 'cancelada' WHERE id = ?", (id,))
            flash("Reserva cancelada correctamente.", "info")

        else:
            flash("Acción no permitida para el estado actual de la reserva.", "warning")

        conn.commit()
    except Exception:
        conn.rollback()
        flash("Error al procesar la operación.", "danger")
    finally:
        conn.close()

    return redirect(url_for("reservas"))

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
