const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const http = require("http");
const socketIo = require("socket.io");
const crypto = require("crypto");
const cors = require("cors");

// Configuración inicial
dotenv.config();
const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: { origin: "*", methods: ["GET", "POST"] },
});

// Configurar CORS para Express
app.use(cors({
  origin: ["http://localhost:5173", "https://tu-dominio-de-frontend.com"],
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));
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

    // Seed para categorías (solo si no existen)
    const categoriasIniciales = [
      { nombre: "Impresoras", descripcion: "Impresoras de diversas marcas" },
      { nombre: "Cables", descripcion: "Cables USB, HDMI, etc." },
      { nombre: "Pantallas", descripcion: "Pantallas y monitores" },
      { nombre: "Gaming", descripcion: "Productos para gaming" },
      { nombre: "Monitores", descripcion: "Monitores de alta calidad" },
      { nombre: "Laptops", descripcion: "Laptops y portátiles" },
      { nombre: "Cargadores", descripcion: "Cargadores para dispositivos" },
      { nombre: "Mouse", descripcion: "Ratones para PC" },
      { nombre: "Teclados", descripcion: "Teclados mecánicos y estándar" },
      { nombre: "Partes de pc", descripcion: "Componentes para PC" },
      { nombre: "Cámaras de Seguridad", descripcion: "Cámaras de vigilancia" },
    ];

    for (const cat of categoriasIniciales) {
      const exists = await Categoria.findOne({ nombre: cat.nombre });
      if (!exists) {
        const id = await obtenerSiguienteSecuencia("categoriaId");
        await new Categoria({ id_categoria: id, ...cat }).save();
        console.log(`Categoría ${cat.nombre} creada`);
      }
    }
  })
  .catch((error) => console.error("Error al conectar a MongoDB:", error.message));

// Modelos (Esquemas de Mongoose)
const counterSchema = new mongoose.Schema({ _id: String, seq: { type: Number, default: 0 } });
const Counter = mongoose.model("Counter", counterSchema);

const clienteSchema = new mongoose.Schema({
  id_usuario: { type: Number, unique: true },
  nombreCompleto: { type: String, required: true },
  correo: { type: String, required: true, unique: true },
  contrasena: { type: String, required: true },
  fecha: { type: Date, default: Date.now },
  rol: { type: String, default: "user" },
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
  categoria: { type: String, required: true }, // Almacena el nombre de la categoría como string
  nombre: { type: String, required: true },
  price: { type: Number, required: true },
  originalPrice: { type: Number },
  discount: { type: Number },
  image: { type: String, required: true },
  description: { type: String, required: true },
  characteristics: { type: String, required: true },
  productCode: { type: String, required: true },
  rating: { type: Number, default: 4.5 },
  reviews: { type: Number, default: 0 },
  inStock: { type: Boolean, default: true },
  featured: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
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
  if (!token) return res.status(401).json({ mensaje: "No token proporcionado" });
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ mensaje: "Token inválido" });
    req.user = user;
    next();
  });
};

// Middleware para verificar si es admin
const autenticarAdmin = (req, res, next) => {
  if (req.user.rol !== "admin") {
    return res.status(403).json({ mensaje: "Acceso denegado: solo administradores" });
  }
  next();
};

// Rutas
app.get("/", (req, res) => res.send("Welcome to my API"));

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
    if (usuarioExistente) return res.status(400).json({ mensaje: "Usuario ya existe" });

    const rol = correo.endsWith("@srrobot.com") ? "admin" : "user";
    const contrasenaEncriptada = await bcrypt.hash(contrasena, 10);
    const id = await obtenerSiguienteSecuencia("clienteId");
    const cliente = new Cliente({
      id_usuario: id,
      nombreCompleto,
      correo,
      contrasena: contrasenaEncriptada,
      rol,
    });
    await cliente.save();
    res.status(201).json({ mensaje: "Usuario registrado", rol });
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
      { id: cliente._id, rol: cliente.rol },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.json({ token, rol: cliente.rol });
  } catch (err) {
    res.status(500).json({ mensaje: "Error: " + err.message });
  }
});

// Rutas de productos
app.get("/api/productos", autenticarToken, async (req, res) => {
  try {
    const productos = await Producto.find();
    res.json(productos);
  } catch (err) {
    res.status(500).json({ mensaje: "Error al obtener productos: " + err.message });
  }
});

app.post("/api/productos", autenticarToken, autenticarAdmin, async (req, res) => {
  try {
    const {
      name,
      category,
      price,
      originalPrice,
      discount,
      image,
      description,
      characteristics,
      productCode,
      inStock,
      rating,
      reviews,
      featured,
    } = req.body;

    // Validaciones
    if (!name || !category || !price || !image || !description || !characteristics || !productCode) {
      return res.status(400).json({ mensaje: "Todos los campos requeridos deben estar presentes" });
    }
    if (isNaN(price) || price <= 0 || price > 10000) {
      return res.status(400).json({ mensaje: "El precio debe ser un número entre 0.01 y 10000" });
    }
    if (discount && (isNaN(discount) || discount < 0 || discount > 100)) {
      return res.status(400).json({ mensaje: "El descuento debe ser un número entre 0 y 100" });
    }
    if (originalPrice && (isNaN(originalPrice) || originalPrice <= 0)) {
      return res.status(400).json({ mensaje: "El precio original debe ser un número positivo" });
    }
    // Validar URL de imagen
    try {
      new URL(image);
    } catch {
      return res.status(400).json({ mensaje: "La URL de la imagen es inválida" });
    }
    // Validar categoría existente
    const categoriaExiste = await Categoria.findOne({ nombre: category });
    if (!categoriaExiste) {
      return res.status(400).json({ mensaje: `La categoría "${category}" no existe` });
    }

    const id = await obtenerSiguienteSecuencia("productoId");
    const producto = new Producto({
      id_producto: id,
      categoria: category, // Almacena el nombre de la categoría como string
      nombre: name,
      price,
      originalPrice,
      discount,
      image,
      description,
      characteristics,
      productCode,
      inStock: inStock !== undefined ? inStock : true,
      rating: rating || 4.5,
      reviews: reviews || 0,
      featured: featured || false,
      createdAt: new Date(),
    });

    await producto.save();
    io.emit("nuevoProducto", producto); // Notificar a los clientes conectados
    res.status(201).json({ mensaje: "Producto creado con éxito", producto });
  } catch (err) {
    res.status(500).json({ mensaje: "Error al crear producto: " + err.message });
  }
});

// Socket.IO para eventos en tiempo real
io.on("connection", (socket) => {
  console.log("Cliente conectado");
  socket.on("disconnect", () => console.log("Cliente desconectado"));
  socket.on("nuevaVenta", (data) => io.emit("actualizarVentas", data));
});

// Iniciar servidor
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`Server listening on port ${PORT}`));