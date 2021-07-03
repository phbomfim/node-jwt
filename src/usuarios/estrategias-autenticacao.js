// Utilizaremos as bibliotecas passport/passport-local
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const BearerStrategy = require('passport-http-bearer').Strategy;

const Usuario = require('./usuarios-modelo');
const { InvalidArgumentError } = require('../erros')

const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const blacklist = require('../../redis/manipula-blacklist');

// Função para verificar a existencia daquele usuario no db
function verificaUsuario(usuario) {
    if(!usuario) {
        throw new InvalidArgumentError('Não existe usuário com esse e-mail');
    }
}

async function verificaTokenNaBlacklist(token) {
    const tokenNaBlacklist = await blacklist.contemToken(token);
    if (tokenNaBlacklist){
        throw new jwt.JsonWebTokenError('TOken inválido por logout!');
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
            await verificaSenha(senha, usuario.senhaHash);

            done(null, usuario);
        } catch (erro){
            done(erro);
        }
    })
);

passport.use(
    new BearerStrategy(
        async (token, done) => {
            try {
                    await verificaTokenNaBlacklist(token)
                    const payload = jwt.verify(token, process.env.CHAVE_JWT);
                    const usuario = await Usuario.buscaPorId(payload.id);
                    done(null, usuario, { token: token });
            } catch (erro){
                done(erro);
            }
        }
    )
)