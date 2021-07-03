const Usuario = require('./usuarios-modelo');
const { InvalidArgumentError, InternalServerError } = require('../erros');

const jwt = require('jsonwebtoken');

const blacklist = require('../../redis/manipula-blacklist');

// Função definida para a criação do JWT
function criaTokenJWT(usuario) {
  const payload = {
    id: usuario.id
  };

  // Criando token a partir de variavel e definição para tempo de expiração
  const token = jwt.sign(payload, process.env.CHAVE_JWT, { expiresIn: '15m'  });
  return token;
}

module.exports = {
  adiciona: async (req, res) => {
    const { nome, email, senha } = req.body;

    try {
      const usuario = new Usuario({
        nome,
        email
      });

      await usuario.adcionaSenha(senha);

      await usuario.adiciona();

      res.status(201).json();
    } catch (erro) {
      if (erro instanceof InvalidArgumentError) {
        res.status(422).json({ erro: erro.message });
      } else if (erro instanceof InternalServerError) {
        res.status(500).json({ erro: erro.message });
      } else {
        res.status(500).json({ erro: erro.message });
      }
    }
  },

  login: (req, res) => {
    const token = criaTokenJWT(req.user); // Chamamos a função antes de enviarmos a resposta do login
    res.set('Authorization', token); // Neste header conterá o token gerado
    res.status(204).send(); // Esse código 204 indica que os headers são úteis
  },

  logout: async (req, res) => {

    try {
      const token = req.token;
      await blacklist.adiciona(token);
      res.status(204).send();
    } catch (error) {
      res.status(500).json({ erro: erro.message });
    }

  },

  lista: async (req, res) => {
    const usuarios = await Usuario.lista();
    res.json(usuarios);
  },

  deleta: async (req, res) => {
    const usuario = await Usuario.buscaPorId(req.params.id);
    try {
      await usuario.deleta();
      res.status(200).send();
    } catch (erro) {
      res.status(500).json({ erro: erro });
    }
  }
};
