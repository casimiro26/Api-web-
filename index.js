const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const http = require("http");
const socketIo = require("socket.io");
const crypto = require("crypto");

// Configuración inicial
dotenv.config();
const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: { origin: "*", methods: ["GET", "POST"] },
});
app.use(express.json());

// Generar secreto JWT si no existe en .env
const generateJWTSecret = () => {
  if (!process.env.JWT_SECRET) {
    const secret = crypto.randomBytes(32).toString("hex");
    console.log("Tu secreto JWT generado (guárdalo en .env):", secret);
    process.env.JWT_SECRET = secret; // Temporal para esta sesión
  }
};
generateJWTSecret();

// Conexión a MongoDB
mongoose
  .connect(process.env.MONGODB_URI)
  .then(async () => {
    console.log("Connected to MongoDB Atlas");

    // Seed para admin (solo si no existe)
    const adminEmail = "admin@srrobot.com";
    const adminExists = await Cliente.findOne({ correo: adminEmail });
    if (!adminExists) {
      const hashed = await bcrypt.hash("SrRobot2024!", 10);
      await new Cliente({
        _id: "68e3fd8a89e2be410e79815d",
        id_usuario: 1,
        nombreCompleto: "Admin SrRobot",
        correo: adminEmail,
        contrasena: hashed,
        rol: "admin",
        fecha: new Date(),
      }).save();
      console.log("Admin creado");
    }
  })
  .catch((error) => console.error("Error al conectar a MongoDB:", error.message));

// Modelos (Esquemas de Mongoose)
const counterSchema = new mongoose.Schema({ _id: String, seq: { type: Number, default: 0 } });
const Counter = mongoose.model("Counter", counterSchema);

const administradorSchema = new mongoose.Schema({
  id_administrador: { type: Number, unique: true },
  nombreCompleto: { type: String, required: true },
  correo: { type: String, required: true, unique: true },
  rol: { type: String, required: true },
});
const Administrador = mongoose.model("Administrador", administradorSchema);

const clienteSchema = new mongoose.Schema({
  id_usuario: { type: Number, unique: true },
  nombreCompleto: { type: String, required: true },
  correo: { type: String, required: true, unique: true },
  contrasena: { type: String, required: true },
  fecha: { type: Date, default: Date.now },
  rol: { type: String, default: "user" }, // Añadido campo rol con default 'user'
});
const Cliente = mongoose.model("Cliente", clienteSchema);

const categoriaSchema = new mongoose.Schema({
  id_categoria: { type: Number, unique: true },
  nombre: { type: String, required: true },
  descripcion: { type: String },
});
const Categoria = mongoose.model("Categoria", categoriaSchema);

const productoSchema = new mongoose.Schema({
  id_producto: { type: Number, unique: true },
  categoria: { type: mongoose.Schema.Types.ObjectId, ref: "Categoria" },
  nombre_producto: { type: String, required: true },
  precio_unitario: { type: Number, required: true },
  stock_actual: { type: Number, required: true },
  stock_minimo: { type: Number },
  codigos: { type: String },
  caracteristicas: { type: String },
  unidad: { type: String },
  estado: { type: String },
});
const Producto = mongoose.model("Producto", productoSchema);

// Utilidad para IDs secuenciales
async function obtenerSiguienteSecuencia(nombre) {
  const contador = await Counter.findOneAndUpdate(
    { _id: nombre },
    { $inc: { seq: 1 } },
    { new: true, upsert: true }
  );
  return contador.seq;
}

// Middleware de autenticación
const autenticarToken = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) return res.status(401).json({ mensaje: "No token" });
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ mensaje: "Token inválido" });
    req.user = user;
    next();
  });
};

// Rutas
// Ruta raíz de prueba
app.get("/", (req, res) => res.send("Welcome to my API"));

// Ruta de prueba original
app.post("/test", async (req, res) => {
  try {
    const testDoc = new mongoose.model("Test", new mongoose.Schema({ name: String }))({ name: "Prueba" });
    await testDoc.save();
    res.send("Documento guardado en la base de datos");
  } catch (error) {
    res.status(500).send("Error al guardar: " + error.message);
  }
});

// Rutas de autenticación
app.post("/api/auth/registrar", async (req, res) => {
  try {
    const { nombreCompleto, correo, contrasena } = req.body;
    if (!nombreCompleto || !correo || !contrasena) {
      return res.status(400).json({ mensaje: "Todos los campos son requeridos" });
    }
    const usuarioExistente = await Cliente.findOne({ correo });
    if (usuarioExistente) return res.status(400).json({ mensaje: "Usuario existe" });
    const contrasenaEncriptada = await bcrypt.hash(contrasena, 10);
    const id = await obtenerSiguienteSecuencia("clienteId");
    const cliente = new Cliente({
      id_usuario: id,
      nombreCompleto,
      correo,
      contrasena: contrasenaEncriptada,
      rol: "user", // Fija el rol como 'user' para nuevos registros
    });
    await cliente.save();
    res.status(201).json({ mensaje: "Usuario registrado" });
  } catch (err) {
    res.status(500).json({ mensaje: "Error: " + err.message });
  }
});

app.post("/api/auth/iniciar-sesion", async (req, res) => {
  try {
    const { correo, contrasena } = req.body;
    const cliente = await Cliente.findOne({ correo });
    if (!cliente || !(await bcrypt.compare(contrasena, cliente.contrasena))) {
      return res.status(400).json({ mensaje: "Credenciales inválidas" });
    }
    const token = jwt.sign(
      { id: cliente._id, rol: cliente.rol }, // Incluye el rol en el token
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.json({ token, rol: cliente.rol }); // Devuelve el rol al frontend
  } catch (err) {
    res.status(500).json({ mensaje: "Error: " + err.message });
  }
});

// Ejemplo de ruta protegida (Productos)
app.get("/api/productos", autenticarToken, async (req, res) => {
  try {
    const productos = await Producto.find();
    res.json(productos);
  } catch (err) {
    res.status(500).json({ mensaje: err.message });
  }
});

app.post("/api/productos", autenticarToken, async (req, res) => {
  try {
    const id = await obtenerSiguienteSecuencia("productoId");
    const producto = new Producto({ id_producto: id, ...req.body });
    await producto.save();
    res.status(201).json(producto);
  } catch (err) {
    res.status(500).json({ mensaje: err.message });
  }
});

// Socket.IO para eventos en tiempo real
io.on("connection", (socket) => {
  console.log("Cliente conectado");
  socket.on("disconnect", () => console.log("Cliente desconectado"));
  socket.on("nuevaVenta", (data) => io.emit("actualizarVentas", data));
});

// Iniciar servidor
const PORT = process.env.PORT || 3000; // Puerto ahora en .env
server.listen(PORT, () => console.log(`Server listening on port ${PORT}`));