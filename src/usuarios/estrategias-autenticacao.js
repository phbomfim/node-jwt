// Utilizaremos as bibliotecas passport/passport-local
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

const Usuario = require('./usuarios-modelo');
const { InvalidArgumentError } = require('../erros')
const bcrypt = require('bcrypt');

// Função para verificar a existencia daquele usuario no db
function verificaUsuario(usuario) {
    if(!usuario) {
        throw new InvalidArgumentError('Não existe usuário com esse e-mail');
    }
}

// Função para verificar se a senha digitada é igual a senhaHash associada para aquele usuario,
// utilizando a função .compare() do bcrypt.
async function verificaSenha(senha, senhaHash){
    const senhaValida = await bcrypt.compare(senha, senhaHash);
    if (!senhaValida){
        throw new InvalidArgumentError('Email ou senha inválidos')
    }
}

// A utilização do passport se dá de acordo a passagem de parametros
passport.use(
    new LocalStrategy({
        usernameField: 'email',
        passwordField: 'senha',
        session: false
    }, async (email, senha, done) => { 

        try {
            const usuario = await Usuario.buscaPorEmail(email);
            verificaUsuario(usuario);
            await verificaSenha(senha, senhaHash);

            done(null, usuario);
        } catch (erro){
            done(erro);
        }
    })
)