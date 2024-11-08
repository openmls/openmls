// Populate the sidebar
//
// This is a script, and not included directly in the page, to control the total size of the book.
// The TOC contains an entry for each page, so if each page includes a copy of the TOC,
// the total size of the page becomes O(n**2).
class MDBookSidebarScrollbox extends HTMLElement {
    constructor() {
        super();
    }
    connectedCallback() {
        this.innerHTML = '<ol class="chapter"><li class="chapter-item expanded affix "><a href="introduction.html">Introduction</a></li><li class="chapter-item expanded "><a href="user_manual/index.html"><strong aria-hidden="true">1.</strong> User manual</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="user_manual/identity.html"><strong aria-hidden="true">1.1.</strong> Credentials</a></li><li class="chapter-item expanded "><a href="user_manual/create_key_package.html"><strong aria-hidden="true">1.2.</strong> Key packages</a></li><li class="chapter-item expanded "><a href="user_manual/group_config.html"><strong aria-hidden="true">1.3.</strong> Group configuration</a></li><li class="chapter-item expanded "><a href="user_manual/create_group.html"><strong aria-hidden="true">1.4.</strong> Creating groups</a></li><li class="chapter-item expanded "><a href="user_manual/join_from_welcome.html"><strong aria-hidden="true">1.5.</strong> Join a group from a Welcome message</a></li><li class="chapter-item expanded "><a href="user_manual/join_from_external_commit.html"><strong aria-hidden="true">1.6.</strong> Join a group from an External Commit message</a></li><li class="chapter-item expanded "><a href="user_manual/add_members.html"><strong aria-hidden="true">1.7.</strong> Adding members to a group</a></li><li class="chapter-item expanded "><a href="user_manual/remove_members.html"><strong aria-hidden="true">1.8.</strong> Removing members from a group</a></li><li class="chapter-item expanded "><a href="user_manual/updates.html"><strong aria-hidden="true">1.9.</strong> Updating own key package</a></li><li class="chapter-item expanded "><a href="user_manual/aad.html"><strong aria-hidden="true">1.10.</strong> Using Additional Authenticated Data (AAD)</a></li><li class="chapter-item expanded "><a href="user_manual/leaving.html"><strong aria-hidden="true">1.11.</strong> Leaving a group</a></li><li class="chapter-item expanded "><a href="user_manual/custom_proposals.html"><strong aria-hidden="true">1.12.</strong> Custom proposals</a></li><li class="chapter-item expanded "><a href="user_manual/application_messages.html"><strong aria-hidden="true">1.13.</strong> Creating application messages</a></li><li class="chapter-item expanded "><a href="user_manual/commit_to_proposals.html"><strong aria-hidden="true">1.14.</strong> Committing to pending proposals</a></li><li class="chapter-item expanded "><a href="user_manual/processing.html"><strong aria-hidden="true">1.15.</strong> Processing incoming messages</a></li><li class="chapter-item expanded "><a href="user_manual/persistence.html"><strong aria-hidden="true">1.16.</strong> Persistence of group state</a></li><li class="chapter-item expanded "><a href="user_manual/credential_validation.html"><strong aria-hidden="true">1.17.</strong> Credential validation</a></li><li class="chapter-item expanded "><a href="user_manual/wasm.html"><strong aria-hidden="true">1.18.</strong> WebAssembly</a></li></ol></li><li class="chapter-item expanded "><a href="traits/index.html"><strong aria-hidden="true">2.</strong> Traits &amp; External Types</a></li><li><ol class="section"><li class="chapter-item expanded "><a href="traits/traits.html"><strong aria-hidden="true">2.1.</strong> Traits</a></li><li class="chapter-item expanded "><a href="traits/types.html"><strong aria-hidden="true">2.2.</strong> Types</a></li></ol></li><li class="chapter-item expanded "><a href="message_validation.html"><strong aria-hidden="true">3.</strong> Message Validation</a></li><li class="chapter-item expanded "><a href="app_validation.html"><strong aria-hidden="true">4.</strong> App Validation</a></li><li class="chapter-item expanded "><a href="performance.html"><strong aria-hidden="true">5.</strong> Performance</a></li><li class="chapter-item expanded "><a href="forward_secrecy.html"><strong aria-hidden="true">6.</strong> Forward Secrecy</a></li><li class="chapter-item expanded "><a href="release_management.html"><strong aria-hidden="true">7.</strong> Release management</a></li></ol>';
        // Set the current, active page, and reveal it if it's hidden
        let current_page = document.location.href.toString();
        if (current_page.endsWith("/")) {
            current_page += "index.html";
        }
        var links = Array.prototype.slice.call(this.querySelectorAll("a"));
        var l = links.length;
        for (var i = 0; i < l; ++i) {
            var link = links[i];
            var href = link.getAttribute("href");
            if (href && !href.startsWith("#") && !/^(?:[a-z+]+:)?\/\//.test(href)) {
                link.href = path_to_root + href;
            }
            // The "index" page is supposed to alias the first chapter in the book.
            if (link.href === current_page || (i === 0 && path_to_root === "" && current_page.endsWith("/index.html"))) {
                link.classList.add("active");
                var parent = link.parentElement;
                if (parent && parent.classList.contains("chapter-item")) {
                    parent.classList.add("expanded");
                }
                while (parent) {
                    if (parent.tagName === "LI" && parent.previousElementSibling) {
                        if (parent.previousElementSibling.classList.contains("chapter-item")) {
                            parent.previousElementSibling.classList.add("expanded");
                        }
                    }
                    parent = parent.parentElement;
                }
            }
        }
        // Track and set sidebar scroll position
        this.addEventListener('click', function(e) {
            if (e.target.tagName === 'A') {
                sessionStorage.setItem('sidebar-scroll', this.scrollTop);
            }
        }, { passive: true });
        var sidebarScrollTop = sessionStorage.getItem('sidebar-scroll');
        sessionStorage.removeItem('sidebar-scroll');
        if (sidebarScrollTop) {
            // preserve sidebar scroll position when navigating via links within sidebar
            this.scrollTop = sidebarScrollTop;
        } else {
            // scroll sidebar to current active section when navigating via "next/previous chapter" buttons
            var activeSection = document.querySelector('#sidebar .active');
            if (activeSection) {
                activeSection.scrollIntoView({ block: 'center' });
            }
        }
        // Toggle buttons
        var sidebarAnchorToggles = document.querySelectorAll('#sidebar a.toggle');
        function toggleSection(ev) {
            ev.currentTarget.parentElement.classList.toggle('expanded');
        }
        Array.from(sidebarAnchorToggles).forEach(function (el) {
            el.addEventListener('click', toggleSection);
        });
    }
}
window.customElements.define("mdbook-sidebar-scrollbox", MDBookSidebarScrollbox);
