local=cap('A',8_000_000,12_000_000,scope='local');internet=cap('A',4_000_000,6_000_000,scope='internet')
configure([local,internet])
phase('independent',{'ul:local':(6.4,8.8),'ul:internet':(3.2,4.4),'dl:local':(9.6,13.2),'dl:internet':(4.8,6.6)})
combined=cap('A',9_000_000,14_000_000)
configure([combined,local,internet])
# Upper bounds establish cumulative caps; split is scheduler-dependent.
phase('combined',{'ul:combined':(7.2,9.9),'dl:combined':(11.2,15.4),'ul:local':(.1,8.8),'ul:internet':(.1,4.4),'dl:local':(.1,13.2),'dl:internet':(.1,6.6)},
      edit=lambda:configure([combined,local]),after_bands={'ul:combined':(7.2,9.9),'dl:combined':(11.2,15.4),'ul:local':(.1,8.8),'dl:local':(.1,13.2)})
B=40_000_000
configure([cap('A',prio='high',scope='local'),cap('A',prio='low',scope='internet')],ub=B,db=B)
first,second=phase('priority',{'ul:combined':(28,44),'dl:combined':(28,44)},
      edit=lambda:configure([cap('A',prio='low',scope='local'),cap('A',prio='high',scope='internet')],ub=B,db=B),after_bands={'ul:combined':(28,44),'dl:combined':(28,44)})
comparisons={direction:first[direction+':local']>2*first[direction+':internet'] and second[direction+':internet']>2*second[direction+':local'] for direction in ('ul','dl')}
results['priority-swap']=comparisons;record('priority-swap',checks=comparisons,first=first,second=second)
