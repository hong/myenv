" vim:shiftwidth=4:tabstop=4:expandtab
" set background=dark
set nobackup
set nowritebackup
set autoindent
set showcmd
set showmatch
set showmode
set formatoptions+=mM
set noincsearch
set hlsearch
set wrap
set wrapscan
set ruler
set shiftwidth=4
set tabstop=4
set showmode
set novisualbell
set nonumber
" compatible: no, we don't want to act like just 'vi'.
set nocompatible
" lazyredraw: do not update screen while executing macros
set lazyredraw
syntax on

" Use CTRL-T for opening new tabs
noremap   <F4>     :tabnew<CR>
vnoremap  <F4>     <C-C>:tabnew<CR>
inoremap  <F4>     <C-O>:tabnew<CR>

map <F3> :nohlsearch <CR>
imap <F3> :nohlsearch <CR>

map <F5> :bn <CR>
map <F6> :bp <CR>
map <F7> :buffers <CR>
map <F8> :A <CR>

set tags=tags
let Tlist_Inc_Winwidth=0
let Tlist_Show_One_File=1
let Tlist_Exist_OnlyWindow=1
let Tlist_Sort_Type="order" " or name
let Tlist_Display_Prototype=0
let Tlist_Compact_Format=1 " Compact?
let Tlist_GainFocus_On_ToggleOpen=1
let Tlist_Display_Tag_Scope=1
let Tlist_Close_On_Select=0
let Tlist_Enable_Fold_Column=0
let TList_WinWidth=45
map <F2> :TlistToggle <CR>
map <silent> ,tl :TlistToggle<CR>

if has("cscope")
	set csprg=/usr/bin/cscope
	set csto=0
	set cst
	set nocsverb
	if filereadable("cscope.out")
		cs add cscope.out
	elseif $CSCOPE_DB != ""
		cs add $CSCOPE_DB
	endif
	set csverb
endif
