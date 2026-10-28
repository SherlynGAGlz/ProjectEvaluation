// middleware/auth.js

const User = require('../models/user');

let auth = (req, res, next) => {
    const token = req.cookies.auth;
    if (!token) {
        return res.status(401).json({ isAuth: false, error: true, message: 'Authentication required' });
    }

    User.findByToken(token, (err, user) => {
        if (err) {
            return res.status(401).json({ isAuth: false, error: true, message: 'Invalid authentication token' });
        }
        if (!user) return res.status(401).json({ isAuth: false, error: true });

        req.token = token;
        req.user = user;
        next();
    });
};

module.exports = { auth };