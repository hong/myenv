/* Copyright (c) 2006 Gianni Tedesco
 * A simple rbtree implementation which combines left and right handed versions
 * of rotations and rebalancing in to single operations.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>

struct tree {
	struct node *root;
};

struct node {
	struct node *parent;
#define CHILD_LEFT 0
#define CHILD_RIGHT 1
	struct node *child[2];
#define COLOR_RED 0 /* parent is black */
#define COLOR_BLACK 1 /* root and NILs are black */
	int color;
	uint32_t val;
	struct rbuf *rbuf;
};

/* Node allocation */
static struct node *alloc_node(void)
{
	struct node *ret;
	ret = calloc(1, sizeof(*ret));
	return ret;
}

static void free_node(struct node *n)
{
	free(n);
}

/* For any given node, find the previous or next node */
static struct node *node_prev_next(struct node *n, int prev)
{
	if ( n == NULL )
		return NULL;

	if ( n->child[prev ^ 1] ) {
		n = n->child[prev ^ 1];
		while( n->child[prev ^ 0] )
			n = n->child[prev ^ 0];
		return n;
	}else{
		while(n->parent && n != n->parent->child[prev ^ 0] )
			n = n->parent;

		return n->parent;
	}
}
static struct node *node_next(struct node *n)
{
	return node_prev_next(n, 0);
}
static struct node *node_prev(struct node *n)
{
	return node_prev_next(n, 1);
}

/* Here we handle left/right rotations (the 2 are symmetrical) which are
 * sometimes needed to rebalance the tree after modifications
*/
static void do_rotate(struct tree *s, struct node *n, int side)
{
	struct node *opp = n->child[1 ^ side];

	if ( (n->child[1 ^ side] = opp->child[0 ^ side]) )
		opp->child[0 ^ side]->parent = n;
	opp->child[0 ^ side] = n;

	if ( (opp->parent = n->parent) ) {
		if ( n == n->parent->child[0 ^ side] ) {
			n->parent->child[0 ^ side] = opp;
		}else{
			n->parent->child[1 ^ side] = opp;
		}
	}else{
		s->root = opp;
	}
	n->parent = opp;
}

/* Re-balance the tree after an insertion */
static void rebalance(struct tree *s, struct node *n)
{
	struct node *parent, *gparent, *uncle;
	int side;

	while ( (parent = n->parent) ) {

		/* Recursion termination, the tree is balanced */
		if ( parent->color == COLOR_BLACK )
			break;

		/* When your structures have symmetry, your code can
		 * be half the size!
		 */
		gparent = parent->parent;
		side = (parent == gparent->child[1]);
		uncle = gparent->child[1 ^ side];

		/* Check to see if we can live with just recoloring */
		if ( uncle && (uncle->color == COLOR_RED) ) {
			gparent->color = COLOR_RED;
			parent->color = COLOR_BLACK;
			uncle->color = COLOR_BLACK;
			n = gparent;
			continue;
		}

		/* Check to see if we need to do double rotation */
		if ( n == parent->child[1 ^ side] ) {
			struct node *t;

			do_rotate(s, parent, 0 ^ side);
			t = parent;
			parent = n;
			n = t;
		}

		/* If not, we do a single rotation */
		parent->color = COLOR_BLACK;
		gparent->color = COLOR_RED;
		do_rotate(s, gparent, 1 ^ side);
	}

	s->root->color = COLOR_BLACK;
}

/* Re-balance a tree after deletion, probably the most complex bit... */
static void delete_rebalance(struct tree *s,
				struct node *n, struct node *parent)
{
	struct node *other;
	int side;

	while ( ((n == NULL) || n->color == COLOR_BLACK) ) {
		if ( n == s->root)
			break;

		side = (parent->child[1] == n);

		other = parent->child[1 ^ side];

		if ( other->color == COLOR_RED ) {
			other->color = COLOR_BLACK;
			parent->color = COLOR_RED;
			do_rotate(s, parent, 0 ^ side);
			other = parent->child[1 ^ side];
		}

		if ( ((other->child[0 ^ side] == NULL) ||
			(other->child[0 ^ side]->color == COLOR_BLACK)) &&
			((other->child[1 ^ side] == NULL) ||
			(other->child[1 ^ side]->color == COLOR_BLACK)) ) {
			other->color = COLOR_RED;
			n = parent;
			parent = n->parent;
		}else{
			if ( (other->child[1 ^ side] == NULL) ||
			(other->child[1 ^ side]->color == COLOR_BLACK) ) {
				struct node *opp;

				if ( (opp = other->child[0 ^ side]) )
					opp->color = COLOR_BLACK;

				other->color = COLOR_RED;
				do_rotate(s, other, 0 ^ side);
				other = parent->child[1 ^ side];
			}

			other->color = parent->color;
			parent->color = COLOR_BLACK;
			if ( other->child[1 ^ side] )
				other->child[1 ^ side]->color = COLOR_BLACK;
			do_rotate(s, parent, 0 ^ side);
			n = s->root;
			break;
		}
	}

	if ( n )
		n->color = COLOR_BLACK;
}

static void delete_node(struct tree *s, struct node *n)
{
	struct node *child, *parent;
	int color;

	if ( n->child[0] && n->child[1] ) {
		struct node *old = n, *lm;

		/* If we have 2 children, go right, and then find the leftmost
		 * node in that subtree, this is the one to swap in to replace
		 * our deleted node
		 */
		n = n->child[1];
		while ( (lm = n->child[0]) != NULL )
			n = lm;

		child = n->child[1];
		parent = n->parent;
		color = n->color;

		if ( child )
			child->parent = parent;

		if ( parent ) {
			if ( parent->child[0] == n )
				parent->child[0] = child;
			else
				parent->child[1] = child;
		}else
			s->root = child;

		if ( n->parent == old )
			parent = n;

		n->parent = old->parent;
		n->color = old->color;
		n->child[0] = old->child[0];
		n->child[1] = old->child[1];

		if ( old->parent ) {
			if ( old->parent->child[0] == old )
				old->parent->child[0] = n;
			else
				old->parent->child[1] = n;
		}else
			s->root = n;

		old->child[0]->parent = n;
		if ( old->child[1] )
			old->child[1]->parent = n;

		goto rebalance;
	}

	if ( n->child[0] == NULL ) {
		child = n->child[1];
	}else if ( n->child[1] == NULL ) {
		child = n->child[0];
	}

	parent = n->parent;
	color = n->color;

	if ( child )
		child->parent = parent;

	if ( parent ) {
		if ( parent->child[0] == n )
			parent->child[0] = child;
		else
			parent->child[1] = child;
	}else
		s->root = child;

rebalance:
	if ( color == COLOR_BLACK )
		delete_rebalance(s, child, parent);
}

/* Allocates a new node ready for insertion in to the tree with the given
 * particulars.
 */
static struct node *new_node(struct tree *s, uint32_t val)
{
	struct node *n;

	n = alloc_node();
	if ( n == NULL )
		return NULL;

	n->val = val;
	n->color = COLOR_RED;

	return n;
}

/* Insert a node in to the tree */
static void insert_node(struct tree *s, uint32_t val)
{
	struct node *n, *parent, **p, *prev, *next;
	int side;

	for(p=&s->root, n = parent = NULL; *p; ) {
		parent = *p;

		//if ( val == parent->val )
		//	return;
		if ( val < parent->val )
			side = 0;
		else
			side = 1;

		p = &(*p)->child[side];
	}

	if ( parent == NULL ) {
		prev = next = NULL;
		goto do_insert;
	}

	if ( p == &parent->child[0] ) {
		prev = node_prev(parent);
		next = parent;
	}else{
		prev = parent;
		next = node_next(parent);
	}

do_insert:

	n = new_node(s, val);
	if ( n == NULL )
		return;

	n->parent = parent;
	*p = n;

	rebalance(s, n);
}

/* Pretty self explanatory */
static void do_find_node(struct node *n, uint32_t val)
{
	if ( n == NULL )
		return;

	printf("iter: %u\n", n->val);
	if ( val < n->val )
		do_find_node(n->child[0], val);
	if ( n->val == val )
		printf(" found: 0x%.8x (%u)\n", n->val, n->val);
	if ( val >= n->val )
		do_find_node(n->child[1], val);
}

static void find_node(struct tree *s, uint32_t val)
{
	do_find_node(s->root, val);
}


/* Print out all nodes in the tree, in tree-order */
static void do_print_tree(struct node *n)
{
	if ( n == NULL )
		return;

	do_print_tree(n->child[0]);
	printf(" area: 0x%.8x (%u)\n", n->val, n->val);
	do_print_tree(n->child[1]);
}

static void print_tree(struct tree *s)
{
	do_print_tree(s->root);
}

int main(int argc, char **argv)
{
	static struct tree s;

	insert_node(&s, 100);
	insert_node(&s, 100);
	insert_node(&s, 2);
	insert_node(&s, 2);
	insert_node(&s, 1);
	insert_node(&s, 1);
	insert_node(&s, 3);
	insert_node(&s, 3);
	insert_node(&s, 0x31337);
	insert_node(&s, 0x31337);
	insert_node(&s, 10);
	insert_node(&s, 10);
	insert_node(&s, 1000);
	insert_node(&s, 1000);

	print_tree(&s);

	find_node(&s, 100);
	return 0;
}
