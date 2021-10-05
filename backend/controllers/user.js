const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
//const cryptojs = require('crypto-js');

const User = require('../models/User');



// On sauvegarde un nouvel utilisateur et crypte son mot de passe avec un hash généré par bcrypt
exports.signup = (req, res, next) => {
  // On appelle la méthode hash de bcrypt et on lui passe le mdp de l'utilisateur, le salte (10) ce sera le nombre de tours qu'on fait faire à l'algorithme
  bcrypt.hash(req.body.password, 10)
    // On récupère le hash de mdp qu'on va enregister en tant que nouvel utilisateur dans la BBD mongoDB
    .then(hash => {
      // Création du nouvel utilisateur avec le model mongoose
      const user = new User({
        // On passe l'email qu'on trouve dans le corps de la requête
        email: req.body.email,
        // On récupère le mdp hashé de bcrypt
        password: hash
      });
      // On enregistre l'utilisateur dans la base de données
      user.save()
        .then(() => res.status(201).json({
          message: 'Utilisateur créé !'
        }))
        .catch(error => res.status(400).json({
          error
        })); // Si il existe déjà un utilisateur avec cette adresse email
    })
    .catch(error => res.status(500).json({
      error
    }));

};

// Le Middleware pour la connexion d'un utilisateur vérifie si l'utilisateur existe dans la base MongoDB lors du login
//si oui il vérifie son mot de passe, s'il est bon il renvoie un TOKEN contenant l'id de l'utilisateur, sinon il renvoie une erreur
exports.login = (req, res, next) => {
  // On doit trouver l'utilisateur dans la BDD qui correspond à l'adresse entrée par l'utilisateur
  User.findOne({
      email: req.body.email
    })
    .then(user => {
      // Si on trouve pas l'utilisateur on va renvoyer un code 401 "non autorisé"
      if (!user) {
        return res.status(401).json({
          error: 'Utilisateur non trouvé !'
        });
      }
      // On utilise bcrypt pour comparer les hashs et savoir si ils ont la même string d'origine
      bcrypt.compare(req.body.password, user.password)
        .then(valid => {
          // Si false, c'est que ce n'est pas le bon utilisateur, ou le mot de passe est incorrect
          if (!valid) {
            return res.status(401).json({
              error: 'Mot de passe incorrect !'
            });
          }
          // Si true, on renvoie un statut 200 et un objet JSON avec un userID + un token
          res.status(200).json({ // Le serveur backend renvoie un token au frontend
            userId: user._id,
            // Permet de vérifier si la requête est authentifiée
            // on va pouvoir obtenir un token encodé pour cette authentification grâce à jsonwebtoken, on va créer des tokens et les vérifier
            token: jwt.sign( // Encode un nouveau token avec une chaine de développement temporaire
              {
                userId: user._id
              }, // Encodage de l'userdID nécéssaire dans le cas où une requête transmettrait un userId (ex: modification d'une sauce)
              'RANDOM_TOKEN_SECRET', // Clé d'encodage du token qui peut être rendue plus complexe en production
              // Argument de configuration avec une expiration au bout de 24h
              {
                expiresIn: '24h'
              }
            )
            // On encode le userID pour la création de nouveaux objets, et cela permet d'appliquer le bon userID
            // aux objets et ne pas modifier les objets des autres
          });
        })
        .catch(error => res.status(500).json({
          error
        }));
    })
    .catch(error => res.status(500).json({
      error
    }));
};
/*
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
};*/
