
const API_BASE = 'http://localhost:5000';

function $(id){ return document.getElementById(id); }
function show(id){ const el = $(id); if(el) el.classList.remove('hidden'); }
function hide(id){ const el = $(id); if(el) el.classList.add('hidden'); }

function toast(msg){
  const t = $('toast');
  if(!t) return console.log('toast:', msg);
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(()=> t.classList.remove('show'), 2000);
}

function token(){ return localStorage.getItem('token'); }
function saveToken(t){ if(t) localStorage.setItem('token', t); else localStorage.removeItem('token'); }
function parseJWT(t){ try { return JSON.parse(atob(t.split('.')[1])); } catch { return {}; } }

// Robust API
async function api(path, opts = {}){
  opts.headers = opts.headers || {};

  if(token()) opts.headers['Authorization'] = 'Bearer ' + token();

  if(opts.body && typeof opts.body !== 'string'){
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(opts.body);
  }

  let res;
  try { res = await fetch(API_BASE + path, opts); }
  catch (err) {
    return { status: 0, body: 'Network error: ' + err.message };
  }

  let txt = '';
  try { txt = await res.text(); } catch(e){ txt = ''; }

  try { return { status: res.status, body: JSON.parse(txt) }; }
  catch { return { status: res.status, body: txt }; }
}

function escapeHtml(str){
  if(typeof str !== 'string') return String(str || '');
  return str.replace(/[&<>"'`=\/]/g, s => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;',
    '/':'&#x2F;','=':'&#x3D;','`':'&#x60;'
  })[s]);
}

// ==========================
// Auth Tabs (Login/Register/Forgot)
// ==========================
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');

    const name = tab.dataset.tab;
    ['login','register','forgot'].forEach(x=>{
      if(x === name) show(`tab_${x}`);
      else hide(`tab_${x}`);
    });
  });
});

// ==========================
// Dashboard Init
// ==========================
let userRole = null;

async function ensureRole(){
  const r = await api('/api/me');
  if(r.status === 200 && r.body) userRole = r.body.role || null;
}

async function initDashboard(){
  hide('auth_view');
  show('dashboard_view');

  await ensureRole();
  updateAdminPanelVisibility();
  const bt = $('btn_logout'); if(bt) bt.style.display = 'inline-block';

  await loadTours();
  await loadFriends();
  await loadFriendRequests();
  await loadJoinedTours();
  await loadChatGroups();
}

// ==========================
// Load View on Refresh
// ==========================

$('btn_refresh').onclick=loadTours;


window.addEventListener('load', async () => {
  hide('admin_panel');

  const t = token();
  if(!t){
    show('auth_view');
    hide('dashboard_view');
    return;
  }

  const r = await api('/api/me');

  if(r.status === 200){
    await initDashboard();
  } else {
    saveToken(null);
    show('auth_view');
    hide('dashboard_view');
  }
});


// ==========================
// AUTH — Register / Login / Forgot
// ==========================
const btnRegister = $('btn_register');
if(btnRegister){
  btnRegister.addEventListener('click', async ()=>{
    const username = $('reg_username').value.trim();
    const email = $('reg_email').value.trim();
    const password = $('reg_password').value;

    if(!username || !email || !password)
      return toast('Please fill all fields');

    const r = await api('/api/register', {
      method: 'POST',
      body: { username, email, password }
    });

    if(r.status === 200) toast('Registered! You can login now.');
    else toast('Register failed: ' + (r.body?.error || r.body));
  });
}

const btnLogin = $('btn_login');
if(btnLogin){
  btnLogin.addEventListener('click', async ()=>{
    const username = $('login_username').value.trim();
    const password = $('login_password').value;

    if(!username || !password)
      return toast('Enter username and password');

    const r = await api('/api/login', {
      method: 'POST',
      body: { username, password }
    });

    if(r.status === 200 && r.body?.token){
      saveToken(r.body.token);
      toast('Login successful');
      await initDashboard();
    } else {
      toast('Login failed: ' + (r.body?.error || 'Unknown error'));
    }
  });
}

const btnForgot = $('btn_forgot');
if (btnForgot) {
  btnForgot.addEventListener('click', (e) => {
    e.preventDefault();
    const username = $('login_username').value.trim();
    if (!username) return toast('Enter username first');

    const fake = btoa(username + ':' + Math.random().toString(36).substring(2));
    console.log(`Password reset link: ${API_BASE}/api/reset/${fake}`);

    toast('Reset link (demo) printed in console');
  });
}

// ==========================
// Logout
// ==========================
const btnLogoutTop = $('btn_logout');
if(btnLogoutTop){
  btnLogoutTop.addEventListener('click', ()=>{
    saveToken(null);
    show('auth_view');
    hide('dashboard_view');
    btnLogoutTop.style.display = 'none';
    toast('Logged out');
  });
}

// ==========================
// Notify Creator (Join Tour)
// ==========================
async function notifyCreator(tourId){
  await api(`/api/tours/${tourId}/notify-creator`, { method:'POST' });
}

// ==========================
// TOURS
// ==========================
async function loadTours(){
  const r = await api('/api/tours');
  const list = $('tour_list');
  if(!list) return;

  list.innerHTML = '';

  if(Array.isArray(r.body) && r.body.length){
    r.body.forEach(t=>{
      const d = document.createElement('div');
      d.className = 'tour-card';
      d.innerHTML = `
        <div class="tour-head">
          <h4>${escapeHtml(t.title)}</h4>
          <div class="meta">${escapeHtml(t.location || 'Unknown')} • ${t.duration || '?'} days • ₹${t.price}</div>
        </div>
        <p class="desc">${escapeHtml(t.description || 'No description provided.')}</p>
        <div class="card-actions">
          <button class="btn small btn-join-tour" data-id="${t.id}">Join</button>
          <button class="btn small ghost btn-edit-tour" data-id="${t.id}">Edit</button>
          <button class="btn small danger btn-delete-tour" data-id="${t.id}">Delete</button>
        </div>
      `;
      list.appendChild(d);
    });
  } else {
    list.innerHTML = '<p class="muted small">No tours found</p>';
  }
}

const btnCreateTour = $('btn_create_tour');
if (btnCreateTour) {
  btnCreateTour.addEventListener('click', async () => {
    btnCreateTour.disabled = true;  // disable button
    
    const title = $('tour_title').value.trim();
    const location = $('tour_location').value.trim();
    const price = Number($('tour_price').value) || 0;
    const duration = Number($('tour_duration').value) || 0;
    const description = $('tour_description').value.trim();

    if (!title) {
      toast('Title required');
      btnCreateTour.disabled = false;
      return;
    }

    const r = await api('/api/tours', {
      method: 'POST',
      body: { title, location, price, duration, description }
    });

    if (r.status === 200) {
      toast('Created!');
      // Clear inputs
      $('tour_title').value = '';
      $('tour_location').value = '';
      $('tour_price').value = '';
      $('tour_duration').value = '';
      $('tour_description').value = '';
      loadTours();
    } else {
      toast('Create failed: ' + (r.body?.error || r.body));
    }
    btnCreateTour.disabled = false;  // re-enable button
  });
}

// Tour list actions
const tourList = $('tour_list');
if(tourList){
  tourList.addEventListener('click', async (e)=>{
    const id = e.target.dataset.id;
    if(!id) return;

    if(e.target.classList.contains('btn-delete-tour')){
      if(!confirm('Delete this tour?')) return;

      const r = await api(`/api/tours/${id}`, { method:'DELETE' });
      toast(r.status===200 ? 'Deleted' : 'Delete failed');
      loadTours();
    }

    else if(e.target.classList.contains('btn-join-tour')){
      const r = await api(`/api/tours/${id}/join`, { method:'POST' });
      if(r.status === 200){
        toast('Joined tour');
        notifyCreator(id);
      } else toast('Join failed: ' + (r.body?.error || r.body));
    }

    else if(e.target.classList.contains('btn-edit-tour')){
      const newTitle = prompt('New title:');
      const newPrice = prompt('New price:');
      const body = {};
      if(newTitle) body.title = newTitle;
      if(newPrice) body.price = Number(newPrice);

      const r = await api(`/api/tours/${id}`, { method:'PUT', body });
      toast(r.status===200 ? 'Updated' : 'Update failed');
      loadTours();
    }
  });
}

// ==========================
// FRIENDS
// ==========================
const btnSearchFriend = $('btn_search_friend');
if(btnSearchFriend){
  btnSearchFriend.addEventListener('click', async ()=>{
    const q = $('friend_search').value.trim();
    if(!q) return toast('Enter username');

    const r = await api('/api/users?search='+encodeURIComponent(q));
    const list = $('friend_results');

    list.innerHTML = '';

    if(Array.isArray(r.body) && r.body.length){
      r.body.forEach(u=>{
        const li = document.createElement('li');
        li.innerHTML = `
          ${escapeHtml(u.username)}
          <button class="btn small" data-user="${escapeHtml(u.username)}">Add</button>
        `;
        list.appendChild(li);
      });

      list.querySelectorAll('button[data-user]').forEach(btn=>{
        btn.addEventListener('click', async e=>{
          const user = e.target.dataset.user;
          const rr = await api('/api/friend/request', {
            method:'POST',
            body:{ username:user }
          });
          toast(rr.status===200 ? 'Request sent' : 'Failed');
          await loadFriends();
          await loadChatGroups();
        });
      });
    } else {
      list.innerHTML = `<li class="muted">No users found</li>`;
    }
  });
}

async function loadFriends(){
  const r = await api('/api/friend');
  const list = $('friend_list');
  if(!list) return;

  list.innerHTML = '';

  const arr = Array.isArray(r.body) ? r.body : r.body?.friends || [];

  if(arr.length){
    arr.forEach(f=>{
      const li = document.createElement('li');
      li.innerHTML = `
        ${escapeHtml(f.username)}
        <button class="btn small danger" data-username="${escapeHtml(f.username)}">Remove</button>
      `;
      list.appendChild(li);
    });

    list.querySelectorAll('button[data-username]').forEach(btn=>{
      btn.addEventListener('click', async (e)=>{
        const rr = await api('/api/friend/'+encodeURIComponent(e.target.dataset.username), {
          method:'DELETE'
        });
        toast(rr.status===200 ? 'Removed' : 'Remove failed');
        await loadFriends();
        await loadChatGroups();
      });
    });
  } else {
    list.innerHTML = `<li class="muted">No friends yet</li>`;
  }
}


async function loadFriendRequests() {
  const r = await api('/api/friend/request');
  const list = $('friend_requests');
  if (!list) return;

  list.innerHTML = '';

  if (Array.isArray(r.body) && r.body.length) {
    r.body.forEach(req => {
      const li = document.createElement('li');
      li.innerHTML = `
        ${escapeHtml(req.username)}
        <button class="btn small primary btn-accept" data-id="${escapeHtml(req.id)}">Accept</button>
        <button class="btn small danger btn-reject" data-id="${escapeHtml(req.id)}">Reject</button>
      `;
      list.appendChild(li);
    });

    list.querySelectorAll('button.btn-accept').forEach(btn => {
      btn.addEventListener('click', async e => {
        const id = e.target.dataset.id;
        const res = await api(`/api/friend/request/${encodeURIComponent(id)}/accept`, { method: 'POST' });
        toast(res.status === 200 ? 'Friend request accepted' : 'Failed to accept');
        await loadFriendRequests();
        await loadFriends();
        await loadChatGroups();
      });
    });

    list.querySelectorAll('button.btn-reject').forEach(btn => {
      btn.addEventListener('click', async e => {
        const id = e.target.dataset.id;
        const res = await api(`/api/friend/request/${encodeURIComponent(id)}/reject`, { method: 'POST' });
        toast(res.status === 200 ? 'Friend request rejected' : 'Failed to reject');
        await loadFriendRequests();
      });
    });

  } else {
    list.innerHTML = '<li class="muted">No friend requests</li>';
  }
}

async function loadChatGroups() {
  const r = await api('/api/friend');
  const chatList = $('friend_chat_list');
  if (!chatList) return;

  chatList.innerHTML = '';
  const friends = r.body?.friends || [];
  friends.forEach(friend => {
    const li = document.createElement('li');
    li.textContent = friend.username;
    li.dataset.userid = friend.id;
    li.addEventListener('click', () => {
      openFriendChat(friend.id);
    });
    chatList.appendChild(li);
  });

  if (friends.length === 0) {
    chatList.innerHTML = '<li class="muted">No friends yet</li>';
  }
}





// ==========================
// GROUPS + CHAT
// ==========================
const btnJoinGroup = $('btn_join_group');
if(btnJoinGroup){
  btnJoinGroup.addEventListener('click', async ()=>{
    const groupId = $('group_tour_id').value.trim();
    if(!groupId) return toast('Enter group ID');

    const r = await api('/api/groups/join', {
      method:'POST',
      body:{ groupId }
    });

    if(r.status === 200){
      toast('Joined group');
      await loadJoinedTours();
      startChatPolling(groupId);
      show('chat_panel');  // showPanel
    } else toast('Join failed: ' + (r.body?.error || r.body));
  });
}

const btnLeaveGroup = $('btn_leave_group');
if(btnLeaveGroup){
  btnLeaveGroup.addEventListener('click', async ()=>{
    const groupId = $('group_tour_id').value.trim();
    if(!groupId) return toast('Enter group ID');

    const r = await api('/api/groups/leave', {
      method:'POST',
      body:{ groupId }
    });

    if(r.status === 200){
      toast('Left group');
      stopChatPolling();
      $('group_members').textContent = '';
      $('chat_messages').innerHTML = '';
    } else toast('Leave failed');
  });
}

async function loadGroupMembers(groupId){
  const r = await api(`/api/groups/${encodeURIComponent(groupId)}/members`);
  $('group_members').textContent =
    Array.isArray(r.body) && r.body.length
      ? 'Members: ' + r.body.map(x=>x.username).join(', ')
      : 'No members';
}

let chatInterval = null;
let activeChatTourId = null;

function startChatPolling(id){
  stopChatPolling();
  activeChatTourId = id;
  $('chat_box').classList.remove('hidden');
  loadGroupMembers(id);
  fetchChat(id);
  chatInterval = setInterval(()=>fetchChat(id), 2500);
}

function stopChatPolling(){
  if(chatInterval) clearInterval(chatInterval);
  chatInterval = null;
  activeChatTourId = null;
  $('chat_box').classList.add('hidden');
}

async function fetchChat(id){
  const r = await api('/api/chat/'+encodeURIComponent(id));
  const box = $('chat_messages');

  box.innerHTML = '';

  if(Array.isArray(r.body) && r.body.length){
    r.body.forEach(m=>{
      const d = document.createElement('div');
      d.className = 'chat-msg';
      d.innerHTML = `<b>${escapeHtml(m.username)}:</b> ${escapeHtml(m.message)}`;
      box.appendChild(d);
    });
    box.scrollTop = box.scrollHeight;
  } else {
    box.innerHTML = `<div class="muted small">No messages yet</div>`;
  }
}

const btnSendChat = $('btn_send_chat');
if(btnSendChat){
  btnSendChat.addEventListener('click', async ()=>{
    const id = activeChatTourId || $('group_tour_id').value.trim();
    const text = $('chat_input').value.trim();

    if(!id) return toast('Join a group first');
    if(!text) return;

    const r = await api('/api/chat/'+encodeURIComponent(id), {
      method:'POST',
      body:{ message: text }
    });

    if(r.status === 200){
      $('chat_input').value = '';
      fetchChat(id);
    }
  });
}


async function loadJoinedTours() {
  // Fetch tours the user has joined
  const r = await api('/api/tours'); // Modify or create endpoint to fetch only joined tours or include join info
  const joinedList = $('joined_tours');
  if (!joinedList) return;

  // Clear current list
  joinedList.innerHTML = '';

  if (Array.isArray(r.body) && r.body.length) {
    for (const tour of r.body) {
      // Check if user is a member (if API returns extra data), else fetch user's joined tours separately
      if (!tour.groupId) continue;

      const li = document.createElement('li');
      li.innerHTML = `
        ${escapeHtml(tour.title)}
        <button class="btn small btn-chat" data-groupid="${escapeHtml(tour.groupId)}">Chat</button>
      `;
      joinedList.appendChild(li);
    }

    // Add event listeners for chat buttons
    joinedList.querySelectorAll('button.btn-chat').forEach(btn => {
      btn.addEventListener('click', e => {
        const groupId = e.target.dataset.groupid;
        startChatPolling(groupId);
        show('chat_panel'); //showPanel
      });
    });
  } else {
    joinedList.innerHTML = '<li class="muted">You have not joined any tours/groups</li>';
  }
}



// ==========================
// ADMIN PANEL
// ==========================
function updateAdminPanelVisibility(){
  const panel = $('admin_panel');
  const navBtn = $('nav_admin_btn');
  const data = parseJWT(token() || '');
  if(data.role === 'admin') {
    panel.classList.remove('hidden');
    navBtn.classList.remove('hidden');
  } else {
    panel.classList.add('hidden');
    navBtn.classList.add('hidden');
  }
}

const btnAdminQuery = $('btn_admin_query');
if(btnAdminQuery){
  btnAdminQuery.addEventListener('click', async ()=>{
    const q = $('admin_query').value;
    if(!q) return toast('Query required');

    const r = await api('/api/admin/query', {
      method:'POST',
      body:{ q }
    });

    $('admin_response').textContent =
      typeof r.body === 'string' ? r.body : JSON.stringify(r.body,null,2);
  });
}
