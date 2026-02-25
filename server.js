const express = require('express');
const multer = require('multer');
const cors = require('cors');
const fs = require('fs-extra');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'votre_cle_secrete_super_secure';

app.use(cors());
app.use(express.json());

// Path to public/assets/image (where Angular serves static files)
const UPLOAD_DIR = path.join(__dirname, '..', 'frontend', 'public', 'assets', 'image');
const PROFILES_DIR = path.join(__dirname, '..', 'frontend', 'public', 'assets', 'profiles');
const DB_FILE = path.join(__dirname, 'db.json');

// Serve static files from the public/assets directory
app.use('/assets', express.static(path.join(__dirname, '..', 'frontend', 'public', 'assets')));

// Ensure directories exist
fs.ensureDirSync(UPLOAD_DIR);
fs.ensureDirSync(PROFILES_DIR);

// Ensure db.json exists
if (!fs.existsSync(DB_FILE)) {
    fs.writeJsonSync(DB_FILE, { products: [], users: [], messages: [] });
} else {
    // Ensure messages key exists in existing db.json
    const data = fs.readJsonSync(DB_FILE);
    if (!data.messages) {
        data.messages = [];
    }
    if (!data.settings) {
        data.settings = { maxPriceLimit: 1000000 };
    }
    fs.writeJsonSync(DB_FILE, data);
}

// Multer storage for product images
const productStorage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

// Multer storage for profile pictures
const profileStorage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, PROFILES_DIR),
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'user-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const uploadProduct = multer({ storage: productStorage });
const uploadProfile = multer({ storage: profileStorage });

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(403).json({ message: 'Token requis' });

    jwt.verify(token.replace('Bearer ', ''), SECRET_KEY, (err, decoded) => {
        if (err) return res.status(401).json({ message: 'Token invalide' });
        req.userId = decoded.id;
        req.userRole = decoded.role;
        next();
    });
};

// Auth Routes
app.post('/api/auth/register', uploadProfile.single('profilePicture'), async (req, res) => {
    try {
        const { firstName, lastName, email, password } = req.body;
        const data = fs.readJsonSync(DB_FILE);

        if (data.users.find(u => u.email === email)) {
            return res.status(400).json({ message: 'Cet email est déjà utilisé' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const profilePicture = req.file ? `assets/profiles/${req.file.filename}` : 'assets/profiles/default-avatar.png';

        const newUser = {
            id: Date.now(),
            firstName,
            lastName,
            email,
            password: hashedPassword,
            profilePicture,
            role: 'user' // Default role for new users
        };

        data.users.push(newUser);
        fs.writeJsonSync(DB_FILE, data);
        res.status(201).json({ message: 'Utilisateur créé avec succès' });
    } catch (error) {
        res.status(500).json({ message: 'Erreur lors de l\'inscription', error: error.message });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const data = fs.readJsonSync(DB_FILE);

        const user = data.users.find(u => u.email === email);
        if (!user) return res.status(400).json({ message: 'Email ou mot de passe incorrect' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ message: 'Email ou mot de passe incorrect' });

        const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, SECRET_KEY, { expiresIn: '1h' });
        res.json({
            token,
            user: {
                id: user.id,
                firstName: user.firstName,
                lastName: user.lastName,
                email: user.email,
                profilePicture: user.profilePicture,
                role: user.role
            }
        });
    } catch (error) {
        res.status(500).json({ message: 'Erreur lors de la connexion', error: error.message });
    }
});

// Middleware to check if user is admin
const isAdmin = (req, res, next) => {
    verifyToken(req, res, () => {
        // req.userRole is set by verifyToken
        if (req.userRole === 'admin') {
            next();
        } else {
            res.status(403).json({ message: 'Accès refusé. Administrateur uniquement.' });
        }
    });
};

app.put('/api/auth/profile', verifyToken, uploadProfile.single('profilePicture'), async (req, res) => {
    try {
        const data = fs.readJsonSync(DB_FILE);
        const userIndex = data.users.findIndex(u => u.id === req.userId);
        if (userIndex === -1) return res.status(404).json({ message: 'Utilisateur non trouvé' });

        const { firstName, lastName, email } = req.body;
        data.users[userIndex].firstName = firstName || data.users[userIndex].firstName;
        data.users[userIndex].lastName = lastName || data.users[userIndex].lastName;
        data.users[userIndex].email = email || data.users[userIndex].email;

        if (req.file) {
            // Delete old picture if not default
            const oldPic = data.users[userIndex].profilePicture;
            if (oldPic && !oldPic.includes('default-avatar.png')) {
                const oldPath = path.join(__dirname, 'public', oldPic);
                if (fs.existsSync(oldPath)) fs.removeSync(oldPath);
            }
            data.users[userIndex].profilePicture = `assets/profiles/${req.file.filename}`;
        }

        fs.writeJsonSync(DB_FILE, data);
        res.json({
            message: 'Profil mis à jour',
            user: {
                id: data.users[userIndex].id,
                firstName: data.users[userIndex].firstName,
                lastName: data.users[userIndex].lastName,
                email: data.users[userIndex].email,
                profilePicture: data.users[userIndex].profilePicture
            }
        });
    } catch (error) {
        res.status(500).json({ message: 'Erreur mise à jour profil', error: error.message });
    }
});

app.put('/api/auth/password', verifyToken, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const data = fs.readJsonSync(DB_FILE);
        const userIndex = data.users.findIndex(u => u.id === req.userId);

        // Check if user exists (should be caught by verifyToken, but good to double check)
        if (userIndex === -1) return res.status(404).json({ message: 'Utilisateur non trouvé' });

        const isMatch = await bcrypt.compare(currentPassword, data.users[userIndex].password);
        if (!isMatch) return res.status(400).json({ message: 'Mot de passe actuel incorrect' });

        data.users[userIndex].password = await bcrypt.hash(newPassword, 10);
        fs.writeJsonSync(DB_FILE, data);
        res.json({ message: 'Mot de passe modifié avec succès' });
    } catch (error) {
        res.status(500).json({ message: 'Erreur modification mot de passe', error: error.message });
    }
});

// Admin User Management Routes
app.get('/api/admin/users', isAdmin, (req, res) => {
    try {
        const data = fs.readJsonSync(DB_FILE);
        const users = data.users.map(u => {
            const { password, ...userWithoutPassword } = u;
            return userWithoutPassword;
        });
        res.json(users);
    } catch (error) {
        res.status(500).json({ message: 'Erreur lors de la récupération des utilisateurs' });
    }
});

app.post('/api/admin/users', isAdmin, uploadProfile.single('profilePicture'), async (req, res) => {
    try {
        const { firstName, lastName, email, password } = req.body;
        const data = fs.readJsonSync(DB_FILE);

        if (data.users.find(u => u.email === email)) {
            return res.status(400).json({ message: 'Cet email est déjà utilisé' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const profilePicture = req.file ? `assets/profiles/${req.file.filename}` : 'assets/profiles/default-avatar.png';

        const newUser = {
            id: Date.now(),
            firstName,
            lastName,
            email,
            password: hashedPassword,
            profilePicture,
            role: 'user'
        };

        data.users.push(newUser);
        fs.writeJsonSync(DB_FILE, data);
        res.status(201).json({ message: 'Utilisateur créé par l\'administrateur' });
    } catch (error) {
        res.status(500).json({ message: 'Erreur lors de la création de l\'utilisateur', error: error.message });
    }
});

app.put('/api/admin/users/:id/role', isAdmin, (req, res) => {
    try {
        const id = parseInt(req.params.id);
        const { role } = req.body;
        const data = fs.readJsonSync(DB_FILE);
        const userIndex = data.users.findIndex(u => u.id === id);

        if (userIndex === -1) return res.status(404).json({ message: 'Utilisateur non trouvé' });

        data.users[userIndex].role = role;
        fs.writeJsonSync(DB_FILE, data);
        res.json({ message: 'Rôle mis à jour avec succès' });
    } catch (error) {
        res.status(500).json({ message: 'Erreur lors de la mise à jour du rôle' });
    }
});

app.delete('/api/admin/users/:id', isAdmin, (req, res) => {
    try {
        const id = parseInt(req.params.id);
        const data = fs.readJsonSync(DB_FILE);
        const userIndex = data.users.findIndex(u => u.id === id);

        if (userIndex === -1) return res.status(404).json({ message: 'Utilisateur non trouvé' });

        // Prevent admin from deleting themselves
        if (id === req.userId) return res.status(400).json({ message: 'Vous ne pouvez pas supprimer votre propre compte' });

        // Delete profile picture if exists
        const user = data.users[userIndex];
        if (user.profilePicture && !user.profilePicture.includes('default-avatar.png')) {
            const picPath = path.join(__dirname, 'public', user.profilePicture);
            if (fs.existsSync(picPath)) fs.removeSync(picPath);
        }

        data.users.splice(userIndex, 1);
        fs.writeJsonSync(DB_FILE, data);
        res.status(204).send();
    } catch (error) {
        res.status(500).json({ message: 'Erreur lors de la suppression de l\'utilisateur' });
    }
});

// Routes
app.get('/api/products', (req, res) => {
    const data = fs.readJsonSync(DB_FILE);
    res.json(data.products);
});

app.get('/api/products/:id', (req, res) => {
    const id = parseInt(req.params.id);
    const data = fs.readJsonSync(DB_FILE);
    const product = data.products.find(p => p.id === id);
    if (product) {
        res.json(product);
    } else {
        res.status(404).send('Product not found');
    }
});

app.post('/api/products', isAdmin, uploadProduct.single('image'), (req, res) => {
    const productData = JSON.parse(req.body.product);
    const data = fs.readJsonSync(DB_FILE);

    const newProduct = {
        ...productData,
        id: data.products.length > 0 ? Math.max(...data.products.map(p => p.id)) + 1 : 1,
        image: `assets/image/${req.file.filename}`
    };

    data.products.push(newProduct);
    fs.writeJsonSync(DB_FILE, data);

    res.status(201).json(newProduct);
});

app.put('/api/products/:id', isAdmin, uploadProduct.single('image'), (req, res) => {
    const id = parseInt(req.params.id);
    const productData = JSON.parse(req.body.product);
    const data = fs.readJsonSync(DB_FILE);

    const index = data.products.findIndex(p => p.id === id);
    if (index === -1) return res.status(404).send('Product not found');

    let imagePath = data.products[index].image;

    if (req.file) {
        // Delete old image if it exists and is not a placeholder
        const oldImagePath = path.join(__dirname, 'src', imagePath);
        if (fs.existsSync(oldImagePath) && !imagePath.startsWith('http')) {
            fs.removeSync(oldImagePath);
        }
        imagePath = `assets/image/${req.file.filename}`;
    }

    data.products[index] = { ...productData, id, image: imagePath };
    fs.writeJsonSync(DB_FILE, data);

    res.json(data.products[index]);
});

app.delete('/api/products/:id', isAdmin, (req, res) => {
    const id = parseInt(req.params.id);
    const data = fs.readJsonSync(DB_FILE);

    const index = data.products.findIndex(p => p.id === id);
    if (index === -1) return res.status(404).send('Product not found');

    const product = data.products[index];
    const imagePath = path.join(__dirname, 'src', product.image);

    // Delete image file
    if (fs.existsSync(imagePath) && !product.image.startsWith('http')) {
        fs.removeSync(imagePath);
    }

    data.products.splice(index, 1);
    fs.writeJsonSync(DB_FILE, data);

    res.status(204).send();
});

// Message Routes (Contact Form)
app.post('/api/messages', (req, res) => {
    try {
        const { name, email, subject, message } = req.body;
        console.log(`[Server] Message reçu de: ${email}`);
        const data = fs.readJsonSync(DB_FILE);

        const newMessage = {
            id: Date.now(),
            name,
            email,
            subject,
            message,
            date: new Date().toISOString(),
            status: 'unread'
        };

        data.messages.push(newMessage);
        fs.writeJsonSync(DB_FILE, data);
        res.status(201).json({ message: 'Message envoyé avec succès' });
    } catch (error) {
        res.status(500).json({ message: 'Erreur lors de l\'envoi du message' });
    }
});

app.get('/api/admin/messages', isAdmin, (req, res) => {
    try {
        const data = fs.readJsonSync(DB_FILE);
        res.json(data.messages || []);
    } catch (error) {
        res.status(500).json({ message: 'Erreur lors de la récupération des messages' });
    }
});

app.delete('/api/admin/messages/:id', isAdmin, (req, res) => {
    try {
        const id = parseInt(req.params.id);
        const data = fs.readJsonSync(DB_FILE);
        const index = data.messages.findIndex(m => m.id === id);

        if (index === -1) return res.status(404).json({ message: 'Message non trouvé' });

        data.messages.splice(index, 1);
        fs.writeJsonSync(DB_FILE, data);
        res.status(204).send();
    } catch (error) {
        res.status(500).json({ message: 'Erreur lors de la suppression du message' });
    }
});

// Category Routes
app.get('/api/categories', (req, res) => {
    try {
        const data = fs.readJsonSync(DB_FILE);
        res.json(data.categories || []);
    } catch (error) {
        res.status(500).json({ message: 'Erreur lors de la récupération des catégories' });
    }
});

app.post('/api/categories', isAdmin, (req, res) => {
    try {
        const { name } = req.body;
        if (!name) return res.status(400).json({ message: 'Le nom de la catégorie est requis' });

        const data = fs.readJsonSync(DB_FILE);
        if (!data.categories) data.categories = [];

        if (data.categories.includes(name)) {
            return res.status(400).json({ message: 'Cette catégorie existe déjà' });
        }

        data.categories.push(name);
        fs.writeJsonSync(DB_FILE, data);
        res.status(201).json({ name });
    } catch (error) {
        res.status(500).json({ message: 'Erreur lors de la création de la catégorie' });
    }
});

app.delete('/api/categories/:name', isAdmin, (req, res) => {
    try {
        const name = req.params.name;
        const data = fs.readJsonSync(DB_FILE);

        if (!data.categories) return res.status(404).json({ message: 'Catégories non trouvées' });

        const index = data.categories.indexOf(name);
        if (index === -1) return res.status(404).json({ message: 'Catégorie non trouvée' });

        // Remove the category
        data.categories.splice(index, 1);

        // Optional: Update products belonging to this category to 'autres'
        data.products.forEach(p => {
            if (p.category === name) {
                p.category = 'autres';
            }
        });

        // Ensure 'autres' exists if we moved products to it
        if (data.products.some(p => p.category === 'autres') && !data.categories.includes('autres')) {
            data.categories.push('autres');
        }

        fs.writeJsonSync(DB_FILE, data);
        res.status(204).send();
    } catch (error) {
        res.status(500).json({ message: 'Erreur lors de la suppression de la catégorie' });
    }
});

// Settings Routes
app.get('/api/settings', (req, res) => {
    try {
        const data = fs.readJsonSync(DB_FILE);
        res.json(data.settings || { maxPriceLimit: 1000000 });
    } catch (error) {
        res.status(500).json({ message: 'Erreur lors de la récupération des paramètres' });
    }
});

app.put('/api/settings', isAdmin, (req, res) => {
    try {
        const newSettings = req.body;
        const data = fs.readJsonSync(DB_FILE);
        data.settings = { ...data.settings, ...newSettings };
        fs.writeJsonSync(DB_FILE, data);
        res.json(data.settings);
    } catch (error) {
        res.status(500).json({ message: 'Erreur lors de la mise à jour des paramètres' });
    }
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
