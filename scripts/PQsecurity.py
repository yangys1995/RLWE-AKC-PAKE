from math import *

log_infinity = 9999

global_log2_eps = 0

## The root hermite factor delta of BKZ-b
def delta_BKZ(b):
	return ( (pi*b)**(1./b) * b / (2*pi*exp(1)))**(1./(2.*b-2.))



## log_2 of best plausible Quantum Cost of SVP in dimension b
def svp_plausible(b):
	return .2075 * b  # + log(b)/log(2)

## log_2 of best plausible Quantum Cost of SVP in dimension b
def svp_quantum(b):
	return .262 * b  # + log(b)/log(2)

## log_2 of best known Quantum Cost of SVP in dimension b
def svp_classical(b):
	return .292 * b  # + log(b)/log(2)

def nvec_sieve(b):
	return .2075 * b



## Return the cost of the primal attack using m samples and blocksize b (infinity = fail)
def primal_cost(q,n,m,s,b, cost_svp = svp_classical,verbose=False):
	d = n + m
	delta = delta_BKZ(b)
	if verbose:
		print "Primal attacks uses block-size", b, "and ", m, "samples"

	if s * sqrt(b) < delta**(2.*b-d-1) * q**(1.*m /d):
		return cost_svp(b) # + log(n-b)/log(2)
	else:
		return log_infinity


## Return the cost of the dual attack using m samples and blocksize b (infinity = fail)
def dual_cost(q,n,m,s,b, cost_svp = svp_classical, verbose = False):
	global global_log2_eps
	d = n+m
	delta = delta_BKZ(b)
	l = delta**d * q**(1.*n/d)

	tau = l * s / q
	log2_eps = - pi * tau**2 / log(2)
	global_log2_eps = log2_eps
	log2_R = max( 0 , - 2 * log2_eps - nvec_sieve(b) ) 
	if verbose:
		print "Dual attacks uses block-size", b, "and ", m, "samples"
		print "log2(epsilon) = ", log2_eps, "log2 nvector per run", nvec_sieve(b)
	return + cost_svp(b) + log2_R


## Find optimal parameters for a given attack
def optimize_attack(q,n,k,s, cost_attack = primal_cost, cost_svp = svp_classical, verbose = True):
	best_cost = log_infinity
	best_b = 0
	best_m = 0
	for b in range(50,2*n+k+1):
		if cost_svp(b) + log(n-b)/log(2) > best_cost:
			break
		for m in range(max(1,b-n),n+k ):
			cost = cost_attack(q,n,m,s,b, cost_svp)
			if cost<best_cost:
				best_cost = cost
				best_m = m
				best_b = b

	cost_attack(q,n,best_m,s,best_b, cost_svp = svp_classical, verbose = verbose)
	return (best_m,best_b,best_cost)




## Create a report on the best BKZ primal attack
def summarize_params(q,n,s, error_tol, security_only = True):
	print "Parameters : q = ", q, "n = ", n , " sigma^2 = ", s**2


	if not security_only:
		print
		std_dev = sqrt (2* n * s**4 + s**2)
		print "final error std dev", std_dev
		tailcut = error_tol / std_dev
		print "tailcut = ", tailcut
		if tailcut < 20:
			print "Heuristic error proba 2^", log(2* exp(-tailcut**2 / 2))/log(2)

	k = n

	
	(m_pc,b_pc,c_pc) = optimize_attack(q,n,k,s, cost_attack = primal_cost, cost_svp = svp_classical, verbose = False)
	(m_pq,b_pq,c_pq) = optimize_attack(q,n,k,s, cost_attack = primal_cost, cost_svp = svp_quantum, verbose = False)
	(m_pp,b_pp,c_pp) = optimize_attack(q,n,k,s, cost_attack = primal_cost, cost_svp = svp_plausible, verbose = False)

	assert m_pc == m_pq
	assert m_pc == m_pp
	assert b_pc == b_pq
	assert b_pc == b_pp

	print "Primal ", "&", m_pc, "&", b_pc, "&", int(floor(c_pc)), "&", int(floor(c_pq))	, "&", int(floor(c_pp)) 


	(m_pc,b_pc,c_pc) = optimize_attack(q,n,k,s, cost_attack = dual_cost, cost_svp = svp_classical, verbose = True)
	(m_pq,b_pq,c_pq) = optimize_attack(q,n,k,s, cost_attack = dual_cost, cost_svp = svp_quantum, verbose = False)
	(m_pp,b_pp,c_pp) = optimize_attack(q,n,k,s, cost_attack = dual_cost, cost_svp = svp_plausible, verbose = False)

	assert m_pc == m_pq
	assert m_pc == m_pp
	assert b_pc == b_pq
	assert b_pc == b_pp

	print "Dual ", "&", m_pc, "&", b_pc, "&", int(floor(c_pc)), "&", int(floor(c_pq))	, "&", int(floor(c_pp)) 




print "### Ding17 ###"
summarize_params(2**32-1,1024,3.192, 2**32 /8)
print
22

q = 12289
print "### Ours ###"
summarize_params(q,1024,sqrt(16/2),3.*q/4)
print




