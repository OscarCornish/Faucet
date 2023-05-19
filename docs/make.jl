using Documenter, DocumenterMarkdown
using Faucet

makedocs(
    format = Documenter.HTML(),
    sitename = "Faucet",
    modules = [Faucet]
)

# Documenter can also automatically deploy documentation to gh-pages.
# See "Hosting Documentation" and deploydocs() in the Documenter manual
# for more information.
#=deploydocs(
    repo = "<repository url>"
)=#
