// ============================================================
// 🚀 MONTA A ROTA AÍ - SERVIDOR COMPLETO
// ============================================================
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

// ===== SUPABASE =====
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ===== CORS - PERMITE ACESSO DO FRONTEND =====
app.use(cors({ 
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// ===== MIDDLEWARE AUTH =====
const autenticar = (req, res, next) => {
  const auth = req.headers['authorization'];
  if (!auth || !auth.startsWith('Bearer ')) return res.status(401).json({ erro: 'Token não fornecido' });
  try {
    req.usuario = jwt.verify(auth.split(' ')[1], process.env.JWT_SECRET);
    next();
  } catch (e) {
    return res.status(401).json({ erro: 'Token inválido' });
  }
};

// ===== HELPERS =====
const gerarCodigo = () => Math.floor(100000 + Math.random() * 900000).toString();
const previsaoEntrega = (min = 20) => { const d = new Date(); d.setMinutes(d.getMinutes() + min + 20); return d.toISOString(); };

// ============================================================
// HEALTH CHECK
// ============================================================
app.get('/', (req, res) => res.json({ sistema: '🚀 Monta a Rota Aí', status: 'online', versao: '1.0.0' }));
app.get('/health', (req, res) => res.json({ status: 'ok', uptime: process.uptime() }));

// ============================================================
// AUTH
// ============================================================
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, senha } = req.body;
    if (!email || !senha) return res.status(400).json({ erro: 'Email e senha obrigatórios' });
    const { data: u, error } = await supabase.from('usuarios').select('*').eq('email', email.toLowerCase()).eq('status', 'ativo').single();
    if (error || !u) return res.status(401).json({ erro: 'Usuário não encontrado' });
    const ok = await bcrypt.compare(senha, u.senha_hash);
    if (!ok) return res.status(401).json({ erro: 'Senha incorreta' });
    await supabase.from('usuarios').update({ ultimo_login_at: new Date() }).eq('id', u.id);
    const token = jwt.sign({ id: u.id, email: u.email, papel: u.papel, loja_id: u.loja_id, entregador_id: u.entregador_id }, process.env.JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, usuario: { id: u.id, nome: u.nome, email: u.email, papel: u.papel, loja_id: u.loja_id, entregador_id: u.entregador_id } });
  } catch (e) { res.status(500).json({ erro: e.message }); }
});

app.post('/api/auth/cadastrar', async (req, res) => {
  try {
    const { nome, email, senha, papel } = req.body;
    if (!nome || !email || !senha) return res.status(400).json({ erro: 'Dados obrigatórios faltando' });
    const senha_hash = await bcrypt.hash(senha, 10);
    const { data, error } = await supabase.from('usuarios').insert({ nome, email: email.toLowerCase(), senha_hash, papel: papel || 'loja' }).select().single();
    if (error) return res.status(400).json({ erro: error.message });
    res.status(201).json({ mensagem: 'Usuário criado', id: data.id });
  } catch (e) { res.status(500).json({ erro: e.message }); }
});

// ============================================================
// LOJAS
// ============================================================
app.get('/api/lojas', autenticar, async (req, res) => {
  const { data, error } = await supabase.from('lojas').select('*').eq('status', 'ativo').order('nome');
  if (error) return res.status(400).json({ erro: error.message });
  res.json(data);
});

app.post('/api/lojas', autenticar, async (req, res) => {
  try {
    const { nome, cnpj, telefone, endereco } = req.body;
    if (!nome) return res.status(400).json({ erro: 'Nome obrigatório' });
    const { data, error } = await supabase.from('lojas').insert({ nome, cnpj, telefone, endereco, taxa_fixa: 4.50 }).select().single();
    if (error) return res.status(400).json({ erro: error.message });
    res.status(201).json(data);
  } catch (e) { res.status(500).json({ erro: e.message }); }
});

// ============================================================
// ENTREGADORES
// ============================================================
app.get('/api/entregadores', autenticar, async (req, res) => {
  const { status } = req.query;
  let q = supabase.from('entregadores').select('*').order('nome');
  if (status) q = q.eq('status', status);
  const { data, error } = await q;
  if (error) return res.status(400).json({ erro: error.message });
  res.json(data);
});

// ===== 404 e ERROS =====
app.use((req, res) => res.status(404).json({ erro: 'Rota não encontrada' }));
app.use((err, req, res, next) => res.status(500).json({ erro: err.message }));

// ===== INICIAR =====
app.listen(PORT, () => {
  console.log(`✅ Monta a Rota Aí rodando na porta ${PORT}`);
});

module.exports = app;
