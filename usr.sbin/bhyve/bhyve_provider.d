provider netbe {
	probe tap__recv(char *, void *);
	probe tap__send(char *, void *);
};
