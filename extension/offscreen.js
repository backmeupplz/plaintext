// Chrome's background has no page to touch the clipboard from, so it opens this
// one to clear a copied secret after 90 seconds.
chrome.runtime.onMessage.addListener((msg, sender, reply) => {
  if (sender.id !== chrome.runtime.id || msg?.action !== 'wipe-clipboard') return false
  const onCopy = (e) => {
    e.clipboardData.setData('text/plain', '')
    e.preventDefault()
  }
  document.addEventListener('copy', onCopy)
  document.execCommand('copy')
  document.removeEventListener('copy', onCopy)
  reply(true)
  return false
})
