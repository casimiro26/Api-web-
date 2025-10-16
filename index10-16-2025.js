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
  .then(() => {
    console.log("Connected to MongoDB Atlas");
  })
  .catch((error) => console.error("Error al conectar a MongoDB:", error.message));

// Modelos (Esquemas de Mongoose)
const counterSchema = new mongoose.Schema({ _id: String, seq: { type: Number, default: 0 } });
const Counter = mongoose.model("Counter", counterSchema);

const usuarioSchema = new mongoose.Schema({
  id_usuario: { type: Number, unique: true },
  nombreCompleto: { type: String, required: true },
  correo: { type: String, required: true, unique: true },
  contrasena: { type: String, required: true },
  fecha: { type: Date, default: Date.now },
  rol: { type: String, enum: ["admin", "superadmin"], default: "admin" },
});
const Usuario = mongoose.model("Usuario", usuarioSchema);

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

// Middleware para verificar admin o superadmin
const verificarAdminOrSuper = (req, res, next) => {
  if (!["admin", "superadmin"].includes(req.user.rol)) {
    return res.status(403).json({ mensaje: "Acceso denegado: solo administradores o superadmin" });
  }
  next();
};

// Middleware para verificar solo superadmin
const autenticarSuperAdmin = (req, res, next) => {
  if (req.user.rol !== "superadmin") {
    return res.status(403).json({ mensaje: "Acceso denegado: solo superadministradores" });
  }
  next();
};

// Función auxiliar para obtener usuario por rol y ID de MongoDB
async function obtenerUsuarioPorRol(rol, mongoId) {
  if (rol === "admin" || rol === "superadmin") {
    return await Usuario.findById(mongoId);
  } else {
    return await Cliente.findById(mongoId);
  }
}

// Función auxiliar para actualizar usuario por rol y ID de MongoDB
async function actualizarUsuarioPorRol(rol, mongoId, datosActualizados) {
  if (rol === "admin" || rol === "superadmin") {
    return await Usuario.findByIdAndUpdate(mongoId, datosActualizados, { new: true });
  } else {
    return await Cliente.findByIdAndUpdate(mongoId, datosActualizados, { new: true });
  }
}

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

// Endpoint inicial para crear superadmin (público, solo una vez)
app.post("/api/setup/crear-superadmin", async (req, res) => {
  try {
    const { nombreCompleto, correo, contrasena } = req.body;
    if (!nombreCompleto || !correo || !contrasena) {
      return res.status(400).json({ mensaje: "Todos los campos son requeridos" });
    }
    if (!correo.endsWith("@srrobot.com")) {
      return res.status(400).json({ mensaje: "Correo debe ser corporativo @srrobot.com" });
    }
    const superadminExistente = await Usuario.findOne({ rol: "superadmin" });
    if (superadminExistente) {
      return res.status(400).json({ mensaje: "Superadmin ya existe. Usa /api/auth/iniciar-sesion" });
    }
    const usuarioExistente = await Usuario.findOne({ correo });
    if (usuarioExistente) return res.status(400).json({ mensaje: "Correo ya existe" });

    const contrasenaEncriptada = await bcrypt.hash(contrasena, 10);
    const id = await obtenerSiguienteSecuencia("usuarioId");
    const usuario = new Usuario({
      id_usuario: id,
      nombreCompleto,
      correo,
      contrasena: contrasenaEncriptada,
      rol: "superadmin",
    });
    await usuario.save();
    res.status(201).json({ mensaje: "Superadmin creado con éxito", rol: "superadmin" });
  } catch (err) {
    res.status(500).json({ mensaje: "Error: " + err.message });
  }
});

// Endpoint para obtener todas las categorías (protegido por superadmin)
app.get("/api/admin/categorias", autenticarToken, autenticarSuperAdmin, async (req, res) => {
  try {
    const categorias = await Categoria.find();
    res.json({ categorias });
  } catch (err) {
    res.status(500).json({ mensaje: "Error al obtener categorías: " + err.message });
  }
});

// Endpoint para crear categoría (protegido por superadmin)
app.post("/api/admin/crear-categoria", autenticarToken, autenticarSuperAdmin, async (req, res) => {
  try {
    const { nombre, descripcion } = req.body;
    if (!nombre) {
      return res.status(400).json({ mensaje: "El nombre de la categoría es requerido" });
    }
    const categoriaExistente = await Categoria.findOne({ nombre: nombre.trim() });
    if (categoriaExistente) return res.status(400).json({ mensaje: "Categoría ya existe" });

    const id = await obtenerSiguienteSecuencia("categoriaId");
    const categoria = new Categoria({
      id_categoria: id,
      nombre: nombre.trim(),
      descripcion: descripcion ? descripcion.trim() : "",
    });
    await categoria.save();
    res.status(201).json({ mensaje: "Categoría creada con éxito", categoria });
  } catch (err) {
    res.status(500).json({ mensaje: "Error: " + err.message });
  }
});

// Endpoint para actualizar categoría (protegido por superadmin)
app.put("/api/admin/categorias/:id", autenticarToken, autenticarSuperAdmin, async (req, res) => {
  try {
    const id_categoria = parseInt(req.params.id);
    const { nombre, descripcion } = req.body;

    if (!nombre && !descripcion) {
      return res.status(400).json({ mensaje: "Al menos un campo debe ser proporcionado para actualizar" });
    }

    const categoriaExistente = await Categoria.findOne({ id_categoria });
    if (!categoriaExistente) {
      return res.status(404).json({ mensaje: "Categoría no encontrada" });
    }

    const actualizaciones = {};
    if (nombre && nombre.trim() !== categoriaExistente.nombre) {
      const nombreExistente = await Categoria.findOne({ nombre: nombre.trim() });
      if (nombreExistente && nombreExistente.id_categoria !== id_categoria) {
        return res.status(400).json({ mensaje: "El nombre de categoría ya está en uso" });
      }
      actualizaciones.nombre = nombre.trim();
    }
    if (descripcion !== undefined) {
      actualizaciones.descripcion = descripcion ? descripcion.trim() : "";
    }

    if (Object.keys(actualizaciones).length === 0) {
      return res.status(400).json({ mensaje: "No hay cambios válidos para actualizar" });
    }

    const categoriaActualizada = await Categoria.findOneAndUpdate(
      { id_categoria },
      actualizaciones,
      { new: true }
    );
    res.json({ mensaje: "Categoría actualizada con éxito", categoria: categoriaActualizada });
  } catch (err) {
    res.status(500).json({ mensaje: "Error al actualizar categoría: " + err.message });
  }
});

// Endpoint para eliminar categoría (protegido por superadmin)
app.delete("/api/admin/categorias/:id", autenticarToken, autenticarSuperAdmin, async (req, res) => {
  try {
    const id_categoria = parseInt(req.params.id);

    const categoria = await Categoria.findOne({ id_categoria });
    if (!categoria) {
      return res.status(404).json({ mensaje: "Categoría no encontrada" });
    }

    // Opcional: Verificar si hay productos usando esta categoría antes de eliminar
    const productosUsandoCategoria = await Producto.countDocuments({ categoria: categoria.nombre });
    if (productosUsandoCategoria > 0) {
      return res.status(400).json({ mensaje: `No se puede eliminar la categoría "${categoria.nombre}" porque está en uso por ${productosUsandoCategoria} productos` });
    }

    await Categoria.deleteOne({ id_categoria });
    res.json({ mensaje: "Categoría eliminada con éxito" });
  } catch (err) {
    res.status(500).json({ mensaje: "Error al eliminar categoría: " + err.message });
  }
});

// Rutas de autenticación para clientes (solo users normales)
app.post("/api/auth/registrar-cliente", async (req, res) => {
  try {
    const { nombreCompleto, correo, contrasena } = req.body;
    if (!nombreCompleto || !correo || !contrasena) {
      return res.status(400).json({ mensaje: "Todos los campos son requeridos" });
    }
    if (correo.endsWith("@srrobot.com")) {
      return res.status(403).json({ mensaje: "Registro solo para clientes. Admins deben ser creados por superadmin." });
    }
    const usuarioExistente = await Cliente.findOne({ correo });
    if (usuarioExistente) return res.status(400).json({ mensaje: "Usuario ya existe" });

    const contrasenaEncriptada = await bcrypt.hash(contrasena, 10);
    const id = await obtenerSiguienteSecuencia("clienteId");
    const cliente = new Cliente({
      id_usuario: id,
      nombreCompleto,
      correo,
      contrasena: contrasenaEncriptada,
      rol: "user",
    });
    await cliente.save();
    res.status(201).json({ mensaje: "Cliente registrado", rol: "user" });
  } catch (err) {
    res.status(500).json({ mensaje: "Error: " + err.message });
  }
});

// Endpoint para crear admin (protegido por superadmin)
app.post("/api/admin/crear-admin", autenticarToken, autenticarSuperAdmin, async (req, res) => {
  try {
    const { nombreCompleto, correo, contrasena } = req.body;
    if (!nombreCompleto || !correo || !contrasena) {
      return res.status(400).json({ mensaje: "Todos los campos son requeridos" });
    }
    if (!correo.endsWith("@srrobot.com")) {
      return res.status(400).json({ mensaje: "Correo debe ser corporativo @srrobot.com" });
    }
    const usuarioExistente = await Usuario.findOne({ correo });
    if (usuarioExistente) return res.status(400).json({ mensaje: "Usuario ya existe" });

    const contrasenaEncriptada = await bcrypt.hash(contrasena, 10);
    const id = await obtenerSiguienteSecuencia("usuarioId");
    const usuario = new Usuario({
      id_usuario: id,
      nombreCompleto,
      correo,
      contrasena: contrasenaEncriptada,
      rol: "admin",
    });
    await usuario.save();
    res.status(201).json({ mensaje: "Admin creado con éxito", rol: "admin" });
  } catch (err) {
    res.status(500).json({ mensaje: "Error: " + err.message });
  }
});

app.post("/api/auth/iniciar-sesion", async (req, res) => {
  try {
    const { correo, contrasena } = req.body;
    let user = await Usuario.findOne({ correo });
    if (user && await bcrypt.compare(contrasena, user.contrasena)) {
      const token = jwt.sign(
        { id: user._id, rol: user.rol },
        process.env.JWT_SECRET,
        { expiresIn: "1h" }
      );
      return res.json({ token, rol: user.rol });
    }
    user = await Cliente.findOne({ correo });
    if (user && await bcrypt.compare(contrasena, user.contrasena)) {
      const token = jwt.sign(
        { id: user._id, rol: user.rol },
        process.env.JWT_SECRET,
        { expiresIn: "1h" }
      );
      return res.json({ token, rol: user.rol });
    }
    return res.status(400).json({ mensaje: "Credenciales inválidas" });
  } catch (err) {
    res.status(500).json({ mensaje: "Error: " + err.message });
  }
});

// Nuevos endpoints para perfiles de usuario (obtener y actualizar perfil propio)
app.get("/api/perfil", autenticarToken, async (req, res) => {
  try {
    const { id: mongoId, rol } = req.user;
    const usuario = await obtenerUsuarioPorRol(rol, mongoId);
    if (!usuario) {
      return res.status(404).json({ mensaje: "Perfil no encontrado" });
    }
    // No incluir contraseña en la respuesta
    const { contrasena, ...perfilSinContrasena } = usuario.toObject();
    res.json({ perfil: perfilSinContrasena });
  } catch (err) {
    res.status(500).json({ mensaje: "Error al obtener perfil: " + err.message });
  }
});

app.put("/api/perfil", autenticarToken, async (req, res) => {
  try {
    const { id: mongoId, rol } = req.user;
    const { nombreCompleto, correo, contrasena: nuevaContrasena } = req.body;

    // Validaciones
    if (!nombreCompleto && !correo && !nuevaContrasena) {
      return res.status(400).json({ mensaje: "Al menos un campo debe ser proporcionado para actualizar" });
    }

    const usuarioExistente = await obtenerUsuarioPorRol(rol, mongoId);
    if (!usuarioExistente) {
      return res.status(404).json({ mensaje: "Perfil no encontrado" });
    }

    const actualizaciones = {};
    if (nombreCompleto && nombreCompleto.trim() !== usuarioExistente.nombreCompleto) {
      actualizaciones.nombreCompleto = nombreCompleto.trim();
    }
    if (correo && correo.trim() !== usuarioExistente.correo) {
      // Verificar unicidad del nuevo correo
      const correoExistente = rol === "user" 
        ? await Cliente.findOne({ correo: correo.trim() }) 
        : await Usuario.findOne({ correo: correo.trim() });
      if (correoExistente && correoExistente._id.toString() !== mongoId.toString()) {
        return res.status(400).json({ mensaje: "El correo ya está en uso" });
      }
      if (rol === "user" && correo.trim().endsWith("@srrobot.com")) {
        return res.status(400).json({ mensaje: "Los clientes no pueden usar correos corporativos" });
      }
      actualizaciones.correo = correo.trim();
    }
    if (nuevaContrasena) {
      const contrasenaEncriptada = await bcrypt.hash(nuevaContrasena, 10);
      actualizaciones.contrasena = contrasenaEncriptada;
    }

    if (Object.keys(actualizaciones).length === 0) {
      return res.status(400).json({ mensaje: "No hay cambios válidos para actualizar" });
    }

    const usuarioActualizado = await actualizarUsuarioPorRol(rol, mongoId, actualizaciones);
    const { contrasena, ...perfilSinContrasena } = usuarioActualizado.toObject();
    res.json({ mensaje: "Perfil actualizado con éxito", perfil: perfilSinContrasena });
  } catch (err) {
    res.status(500).json({ mensaje: "Error al actualizar perfil: " + err.message });
  }
});

// Nuevos endpoints para superadmin: gestionar cuentas administrativas (obtener lista, editar, eliminar)
app.get("/api/superadmin/admins", autenticarToken, autenticarSuperAdmin, async (req, res) => {
  try {
    // Obtener todos los admins (excluyendo superadmin si se desea, pero por ahora todos los Usuario)
    const admins = await Usuario.find({ rol: "admin" }).select("-contrasena"); // Excluir contraseña
    res.json({ admins });
  } catch (err) {
    res.status(500).json({ mensaje: "Error al obtener lista de admins: " + err.message });
  }
});

app.get("/api/superadmin/admins/:id_usuario", autenticarToken, autenticarSuperAdmin, async (req, res) => {
  try {
    const id_usuario = parseInt(req.params.id_usuario);
    const admin = await Usuario.findOne({ id_usuario, rol: "admin" }).select("-contrasena");
    if (!admin) {
      return res.status(404).json({ mensaje: "Admin no encontrado" });
    }
    res.json({ admin });
  } catch (err) {
    res.status(500).json({ mensaje: "Error al obtener admin: " + err.message });
  }
});

app.put("/api/superadmin/admins/:id_usuario", autenticarToken, autenticarSuperAdmin, async (req, res) => {
  try {
    const id_usuario = parseInt(req.params.id_usuario);
    const { nombreCompleto, correo, contrasena: nuevaContrasena } = req.body;

    if (!nombreCompleto && !correo && !nuevaContrasena) {
      return res.status(400).json({ mensaje: "Al menos un campo debe ser proporcionado para actualizar" });
    }

    const adminExistente = await Usuario.findOne({ id_usuario, rol: "admin" });
    if (!adminExistente) {
      return res.status(404).json({ mensaje: "Admin no encontrado" });
    }

    // No permitir editar superadmin (aunque la consulta es solo para admins)
    const superadminId = (await Usuario.findOne({ rol: "superadmin" })).id_usuario;
    if (id_usuario === superadminId) {
      return res.status(403).json({ mensaje: "No se puede editar el superadmin" });
    }

    const actualizaciones = {};
    if (nombreCompleto && nombreCompleto.trim() !== adminExistente.nombreCompleto) {
      actualizaciones.nombreCompleto = nombreCompleto.trim();
    }
    if (correo && correo.trim() !== adminExistente.correo) {
      const correoExistente = await Usuario.findOne({ correo: correo.trim() });
      if (correoExistente && correoExistente.id_usuario !== id_usuario) {
        return res.status(400).json({ mensaje: "El correo ya está en uso" });
      }
      if (!correo.trim().endsWith("@srrobot.com")) {
        return res.status(400).json({ mensaje: "El correo debe ser corporativo @srrobot.com" });
      }
      actualizaciones.correo = correo.trim();
    }
    if (nuevaContrasena) {
      const contrasenaEncriptada = await bcrypt.hash(nuevaContrasena, 10);
      actualizaciones.contrasena = contrasenaEncriptada;
    }

    if (Object.keys(actualizaciones).length === 0) {
      return res.status(400).json({ mensaje: "No hay cambios válidos para actualizar" });
    }

    const adminActualizado = await Usuario.findOneAndUpdate(
      { id_usuario, rol: "admin" },
      actualizaciones,
      { new: true }
    ).select("-contrasena");
    res.json({ mensaje: "Admin actualizado con éxito", admin: adminActualizado });
  } catch (err) {
    res.status(500).json({ mensaje: "Error al actualizar admin: " + err.message });
  }
});

app.delete("/api/superadmin/admins/:id_usuario", autenticarToken, autenticarSuperAdmin, async (req, res) => {
  try {
    const id_usuario = parseInt(req.params.id_usuario);

    const admin = await Usuario.findOne({ id_usuario, rol: "admin" });
    if (!admin) {
      return res.status(404).json({ mensaje: "Admin no encontrado" });
    }

    // No permitir eliminar superadmin
    const superadminId = (await Usuario.findOne({ rol: "superadmin" })).id_usuario;
    if (id_usuario === superadminId) {
      return res.status(403).json({ mensaje: "No se puede eliminar el superadmin" });
    }

    await Usuario.deleteOne({ id_usuario, rol: "admin" });
    res.json({ mensaje: "Admin eliminado con éxito" });
  } catch (err) {
    res.status(500).json({ mensaje: "Error al eliminar admin: " + err.message });
  }
});

// Agregar después de tu endpoint POST /api/productos

// Actualizar producto
app.put("/api/productos/:id", autenticarToken, verificarAdminOrSuper, async (req, res) => {
  try {
    const productId = parseInt(req.params.id);
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
    } = req.body;

    // Limpiar strings
    const cleanName = name?.trim();
    const cleanCategory = category?.trim();
    const cleanImage = image?.trim();
    const cleanDescription = description?.trim();
    const cleanCharacteristics = characteristics?.trim();
    const cleanProductCode = productCode?.trim();

    // Validaciones
    if (!cleanName || !cleanCategory || !price || !cleanImage || !cleanDescription || !cleanCharacteristics || !cleanProductCode) {
      return res.status(400).json({ mensaje: "Todos los campos requeridos deben estar presentes" });
    }

    if (isNaN(price) || price <= 0 || price > 10000) {
      return res.status(400).json({ mensaje: "El precio debe ser un número entre 0.01 y 10000" });
    }

    if (discount && (isNaN(discount) || discount < 0 || discount > 100)) {
      return res.status(400).json({ mensaje: "El descuento debe ser un número entre 0 y 100" });
    }

    // Validar URL de imagen
    try {
      new URL(cleanImage);
    } catch {
      return res.status(400).json({ mensaje: "La URL de la imagen es inválida" });
    }

    // Validar categoría existente
    const categoriaExiste = await Categoria.findOne({ nombre: cleanCategory });
    if (!categoriaExiste) {
      return res.status(400).json({ mensaje: `La categoría "${cleanCategory}" no existe` });
    }

    // Buscar y actualizar producto
    const producto = await Producto.findOne({ id_producto: productId });
    if (!producto) {
      return res.status(404).json({ mensaje: "Producto no encontrado" });
    }

    // Actualizar campos
    producto.nombre = cleanName;
    producto.categoria = cleanCategory;
    producto.price = price;
    producto.originalPrice = originalPrice;
    producto.discount = discount;
    producto.image = cleanImage;
    producto.description = cleanDescription;
    producto.characteristics = cleanCharacteristics;
    producto.productCode = cleanProductCode;
    producto.inStock = inStock !== undefined ? inStock : true;

    await producto.save();
    
    res.json({ mensaje: "Producto actualizado con éxito", producto });
  } catch (err) {
    res.status(500).json({ mensaje: "Error al actualizar producto: " + err.message });
  }
});

// Eliminar producto
app.delete("/api/productos/:id", autenticarToken, verificarAdminOrSuper, async (req, res) => {
  try {
    const productId = parseInt(req.params.id);
    
    const producto = await Producto.findOne({ id_producto: productId });
    if (!producto) {
      return res.status(404).json({ mensaje: "Producto no encontrado" });
    }

    await Producto.deleteOne({ id_producto: productId });
    
    res.json({ mensaje: "Producto eliminado con éxito" });
  } catch (err) {
    res.status(500).json({ mensaje: "Error al eliminar producto: " + err.message });
  }
});

// En tu server.js, después de los modelos y antes de rutas protegidas, agrega estos endpoints PÚBLICOS:

// GET público para productos (sin auth, para frontend)
app.get("/api/productos", async (req, res) => {
  try {
    const productos = await Producto.find().select('-contrasena'); // Excluye sensibles si hay
    res.json(productos);
  } catch (err) {
    res.status(500).json({ mensaje: "Error al obtener productos: " + err.message });
  }
});

// GET público para categorías (sin auth)
app.get("/api/categorias", async (req, res) => {
  try {
    const categorias = await Categoria.find();
    res.json({ categorias });
  } catch (err) {
    res.status(500).json({ mensaje: "Error al obtener categorías: " + err.message });
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

app.post("/api/productos", autenticarToken, verificarAdminOrSuper, async (req, res) => {
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
    } = req.body;

    
    // Limpiar strings para evitar mismatches (trim)
    const cleanName = name?.trim();
    const cleanCategory = category?.trim();
    const cleanImage = image?.trim();
    const cleanDescription = description?.trim();
    const cleanCharacteristics = characteristics?.trim();
    const cleanProductCode = productCode?.trim();

    // Validaciones (solo campos del modal de agregar producto)
    if (!cleanName || !cleanCategory || !price || !cleanImage || !cleanDescription || !cleanCharacteristics || !cleanProductCode) {
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
      new URL(cleanImage);
    } catch {
      return res.status(400).json({ mensaje: "La URL de la imagen es inválida" });
    }
    // Validar categoría existente (con trim para matching)
    const categoriaExiste = await Categoria.findOne({ nombre: cleanCategory });
    if (!categoriaExiste) {
      return res.status(400).json({ mensaje: `La categoría "${cleanCategory}" no existe` });
    }

    const id = await obtenerSiguienteSecuencia("productoId");
    const producto = new Producto({
      id_producto: id,
      categoria: cleanCategory, // Almacena el nombre de la categoría limpia como string
      nombre: cleanName,
      price,
      originalPrice,
      discount,
      image: cleanImage,
      description: cleanDescription,
      characteristics: cleanCharacteristics,
      productCode: cleanProductCode,
      inStock: inStock !== undefined ? inStock : true,
      // Campos no en modal (reviews, featured, createdAt): usar defaults del schema
      // rating también usa default del schema si no se envía
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