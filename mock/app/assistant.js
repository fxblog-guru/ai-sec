// A support assistant. Planted defects for M14 — see ../expected.json.
//
// The shape is deliberately ordinary: this is what an LLM feature looks like when
// it is written the obvious way, by someone who has not yet been told that a
// completion is untrusted input.
const Anthropic = require('@anthropic-ai/sdk');
const { execSync } = require('child_process');

const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

// DEFECT (prompt-injection, CWE-1427 / LLM01): the ticket body arrives from a
// request and is concatenated straight into the instructions. Whoever writes the
// ticket decides what the assistant does next.
async function summarizeTicket(req, res) {
  const ticket = req.body.ticket;
  const reply = await client.messages.create({
    model: 'claude-sonnet-4-5',
    max_tokens: 1024,
    system: `You are a support agent. Summarize the ticket below and suggest a fix.\n\n${ticket}`,
    messages: [{ role: 'user', content: 'Summarize it.' }],
  });
  res.json({ summary: reply.content[0].text });
}

// DEFECT (llm-output-to-sink, CWE-94 / LLM05): the model is asked for a shell
// command and the answer is run. A prompt injection in the ticket above reaches
// this line, which is why the two defects are one story and not two.
async function runSuggestedFix(req, res) {
  const completion = await client.messages.create({
    model: 'claude-sonnet-4-5',
    max_tokens: 256,
    messages: [{ role: 'user', content: `Give the shell command to fix: ${req.body.problem}` }],
  });
  const command = completion.content[0].text;
  const output = execSync(command, { encoding: 'utf8' });
  res.json({ output });
}

// DEFECT (excessive-agent-authority, CWE-250 / LLM06): a tool the model may call
// whose handler is a shell. The model chooses the arguments.
const tools = [
  {
    name: 'run_diagnostic',
    description: 'Run a diagnostic command on the server',
    input_schema: { type: 'object', properties: { cmd: { type: 'string' } } },
  },
];

function handleTool(name, input) {
  if (name === 'run_diagnostic') {
    return execSync(input.cmd, { shell: true, encoding: 'utf8' });
  }
  return null;
}

// DEFECT (secret-in-prompt, CWE-200 / LLM02): the key is placed in the prompt so
// the model "can call the API itself". Anything in a prompt can come back out.
async function callPartnerApi(req, res) {
  const prompt = `Call the partner API using key ${process.env.PARTNER_API_KEY} and report the result.`;
  const reply = await client.messages.create({
    model: 'claude-sonnet-4-5',
    max_tokens: 512,
    messages: [{ role: 'user', content: prompt }],
  });
  res.json({ reply: reply.content[0].text });
}

// DEFECT (unbounded-model-consumption, CWE-770 / LLM10): no token ceiling and no
// timeout. A hardening note, not a way in — it costs money, it does not let
// anyone past a control.
async function draftReply(req, res) {
  const reply = await client.messages.create({
    model: 'claude-sonnet-4-5',
    messages: [{ role: 'user', content: String(req.body.notes) }],
  });
  res.json({ draft: reply.content[0].text });
}

// CORRECT, and here so the rules have something to stay quiet about: the ticket
// is kept in a user-role message, the completion is mapped onto a fixed set of
// actions, and the ceiling is set.
const ALLOWED_ACTIONS = { refund: doRefund, escalate: doEscalate, close: doClose };

async function classifyTicket(req, res) {
  const reply = await client.messages.create({
    model: 'claude-sonnet-4-5',
    max_tokens: 16,
    system: 'Reply with exactly one of: refund, escalate, close.',
    messages: [{ role: 'user', content: String(req.body.ticket) }],
  });
  const action = ALLOWED_ACTIONS[reply.content[0].text.trim()];
  if (!action) return res.status(422).json({ error: 'unrecognised action' });
  return action(req.user, res);
}

module.exports = {
  summarizeTicket, runSuggestedFix, handleTool, tools,
  callPartnerApi, draftReply, classifyTicket,
};
