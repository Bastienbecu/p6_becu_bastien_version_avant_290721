const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
//const cryptojs = require('crypto-js');

const User = require('../models/User');





exports.signup = (req, res, next) => {
  //regex pour exiger un mot de passe fort d'au moins 8 caractères
  //const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[0-9])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z0-9\d@$!%*?&]{8,}$/; 
  const password = req.body.password;
 // const cryptedEmail = cryptojs.HmacSHA256(req.body.email, process.env.EMAIL_ENCRYPTION_KEY).toString();

  if (password.match()) {
  bcrypt.hash(req.body.password, 10)
    .then(hash => {
      const user = new User({
        email: req.body.email,
        password: hash
      });
      user.save()
        .then(() => res.status(201).json({ message: 'Utilisateur créé !' }))
        .catch(error => res.status(400).json({ error }));
    })
    .catch(error => res.status(500).json({ error }));
  } else {
    throw new Error("Le mot de passe n'est pas assez sécurisé");
  }
};

exports.login = (req, res, next) => {
  //const cryptedEmail = cryptojs.HmacSHA256(req.body.email, process.env.EMAIL_ENCRYPTION_KEY).toString();

  User.findOne({ email: req.body.email})
    .then(user => {
      if (!user) {
        return res.status(401).json({ error: 'Utilisateur non trouvé !' });
      }
      bcrypt.compare(req.body.password, user.password)
        .then(valid => {
          if (!valid) {
            return res.status(401).json({ error: 'Mot de passe incorrect !' });
          }
          res.status(200).json({
            //encodage et renvoi au frontend d'un nouveau token contenant le userId en tant que payload
            userId: user._id,
            token: jwt.sign(
              { userId: user._id },
              'RANDOM_TOKEN_SECRET',
              { expiresIn: '24h' }
            )
          });
        })
        .catch(error => res.status(500).json({ error }));
    })
    .catch(error => res.status(500).json({ error }));
};
