// models/user.js

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const config = require('../config/config').get(process.env.NODE_ENV);

const SALT_I = 10;

const userSchema = mongoose.Schema({
    email: {
        type: String,
        required: true,
        trim: true,
        lowercase: true, //Modificacion de sher
        unique: true //Modificación de Sher 
    },
    password: {
        type: String,
        required: true,
        minlength: 6
    },
    firstname: {
        type: String,
        maxlength: 100
    },
    lastname: {
        type: String,
        maxlength: 100
    },
    token: {
        type: String
    }
});

// Encriptar la contraseña antes de guardar el usuario
userSchema.pre('save', function (next) {
    const user = this; //modificacion de sher

    if (!user.isModified('password')) { //modifiaciones de sher
        return next();
    }

    bcrypt.genSalt(SALT_I, function (err, salt) {
        if (err) return next(err);

        bcrypt.hash(user.password, salt, function (err, hash) {
            if (err) return next(err);
            user.password = hash;
            next();
        });
    });
});

// Método para comparar contraseñas en el Login
userSchema.methods.comparepassword = function (candidatePassword, cb) {
    bcrypt.compare(candidatePassword, this.password, function (err, isMatch) {
        if (err) return cb(err);
        cb(null, isMatch);
    });
};

// Generar Token JWT al iniciar sesión
userSchema.methods.generateToken = function (cb) {
    const user = this; //modificacion de sher
    const token = jwt.sign(user._id.toHexString(), config.SECRET);

    user.token = token;
    user.save(function (err, user) {
        if (err) return cb(err);
        cb(null, user);
    });
};

// Método estático para validar un usuario mediante su Token
userSchema.statics.findByToken = function (token, cb) {
    const user = this; //modificacion de sher
//Modificacion de Sher aqui 
    jwt.verify(token, config.SECRET, function (err, decode) {
        if (err) return cb(err);
        user.findOne({ "_id": decode, "token": token }, function (err, user) {
            if (err) return cb(err);
            cb(null, user);
        });
    });
};

// Eliminar token en el Logout
userSchema.methods.deleteToken = function (token, cb) {
    const user = this; //modificacion de sher

    user.updateOne({ $unset: { token: 1 } }, function (err, raw) {
        if (err) return cb(err);
        cb(null, user);
    });
};

const User = mongoose.model('User', userSchema);

module.exports = User;