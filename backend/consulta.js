const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const pool = new Pool({
  host: "localhost",
  user: "postgres",
  password: "497813",
  database: "softjobs",
  allowExitOnIdle: true,
});

const verificarToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) {
    return res.status(401).send("Token no proporcionado");
  }

  jwt.verify(token, "az_AZ", (err, decoded) => {
    if (err) {
      return res.status(403).send("Token inválido o expirado");
    }
    req.user = decoded;
    next();
  });
};

const verificarCredenciales = async (email, password) => {
  const consulta = "SELECT * FROM usuarios WHERE email = $1";
  const values = [email];
  const { rows } = await pool.query(consulta, values);
  console.log("Resultado de la consulta:", rows);
  if (!rows.length) {
    console.error(`No se encontró el usuario con el email: ${email}`);
    throw {
      code: 404,
      message: "No se encontró ningún usuario con este email",
    };
  }

  const usuario = rows[0];
  const passwordMatch = await bcrypt.compare(password, usuario.password);
  if (!passwordMatch) {
    console.error(`Las credenciales para el usuario ${email} no coinciden`);
    throw { code: 401, message: "Credenciales incorrectas" };
  }

  return usuario;
};

const registrarUsuario = async (email, password, rol, lenguage) => {
  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const consulta =
      "INSERT INTO usuarios (email, password, rol, lenguage) VALUES ($1, $2, $3, $4) RETURNING id";
    const values = [email, passwordHash, rol, lenguage];
    const { rows } = await pool.query(consulta, values);
    console.log(`Nuevo usuario registrado con ID: ${rows[0].id}`);
    return rows[0].id;
  } catch (error) {
    console.error("Error al registrar el usuario:", error);
    throw { code: 500, message: "Error al registrar el usuario" };
  }
};

const obtenerUsuario = async (email) => {
  //conexión a base de datos
  const query = "SELECT * FROM usuarios WHERE email = $1";
  const resultado = await pool.query(query, [email]);
  if (resultado.rows.length === 0) {
    throw { code: 404, message: "Usuario no encontrado" };
  }
  return resultado.rows[0];
};

module.exports = {
  verificarCredenciales,
  verificarToken,
  registrarUsuario,
  obtenerUsuario,
};
